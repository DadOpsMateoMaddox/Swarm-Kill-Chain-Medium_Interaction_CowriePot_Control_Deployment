# Invoke-PatriotPot.ps1
#
# Prepares, reviews, and optionally executes the PatriotPot 2026 native
# Amazon Linux 2 control replacement. There is no container build or registry.

[CmdletBinding()]
param(
    [string]$Profile = "patriotpot",
    [string]$Region = "us-east-1",
    [string]$StackName = "patriotpot-2026-control-prod",
    [string]$Environment = "production",
    [string]$ProjectRoot = "C:\DadOpsMateoMaddox\PatriotPot\2026-control",
    [string]$DiscordWebhookParameterName = "/patriotpot/2026-control/discord-webhook",
    [switch]$PreflightOnly,
    [switch]$FirewallOnly,
    [switch]$H2,
    [switch]$ExecuteChangeSet
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($Profile -ne "patriotpot" -or $Region -ne "us-east-1") {
    throw "Mission boundary violation: profile must be patriotpot and region must be us-east-1."
}

$Template = Join-Path $ProjectRoot "gmu-honeypot-stack-2026-control.yaml"
$NativeRoot = Join-Path $ProjectRoot "native"
$SecretName = "patriotpot/2026-control/cowrie-host-key"
$EvidenceBucket = $null

function Section([string]$Message) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $Message
    Write-Host "============================================================"
}

function Invoke-Aws {
    $output = aws @args --profile patriotpot --region us-east-1
    if ($LASTEXITCODE -ne 0) {
        throw "AWS CLI operation failed: aws $($args[0]) $($args[1])"
    }
    return $output
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-AssetMap {
    return [ordered]@{
        "archive-requirements.lock"         = Join-Path $NativeRoot "archive-requirements.lock"
        "cowrie-requirements.lock"          = Join-Path $NativeRoot "cowrie-requirements.lock"
        "discord-monitor.py"                = Join-Path $NativeRoot "discord-monitor.py"
        "s3-archive.py"                     = Join-Path $NativeRoot "s3-archive.py"
        "install-host-key.py"               = Join-Path $NativeRoot "install-host-key.py"
        "cowrie.service"                    = Join-Path $NativeRoot "cowrie.service"
        "patriotpot-discord.service"        = Join-Path $NativeRoot "patriotpot-discord.service"
        "patriotpot-egress-firewall.service" = Join-Path $NativeRoot "patriotpot-egress-firewall.service"
        "patriotpot-archive.service"        = Join-Path $NativeRoot "patriotpot-archive.service"
        "patriotpot-archive.timer"          = Join-Path $NativeRoot "patriotpot-archive.timer"
        "cloudwatch-agent.json"             = Join-Path $NativeRoot "cloudwatch-agent.json"
        "patriotpot-logrotate"              = Join-Path $NativeRoot "patriotpot-logrotate"
        "cowrie.cfg"                        = Join-Path $ProjectRoot "cowrie.cfg"
        "userdb.txt"                        = Join-Path $ProjectRoot "userdb.txt"
        "honeyfs-etc-passwd"                = Join-Path $ProjectRoot "honeyfs-etc-passwd"
        "honeyfs-home-admin-passwords.txt"  = Join-Path $ProjectRoot "honeyfs-home-admin-passwords.txt"
        "txtcmds-bin-netstat"               = Join-Path $ProjectRoot "txtcmds-bin-netstat"
        "txtcmds-bin-ps"                    = Join-Path $ProjectRoot "txtcmds-bin-ps"
        "patriotpot-egress-firewall.sh"     = Join-Path $NativeRoot "patriotpot-egress-firewall.sh"
        "session_cluster.py"                = Join-Path $NativeRoot "session_cluster.py"
        "discord_rate_governor.py"          = Join-Path $NativeRoot "discord_rate_governor.py"
        "threat_intel__init__.py"           = Join-Path $NativeRoot "threat_intel\__init__.py"
        "threat_intel_observables.py"       = Join-Path $NativeRoot "threat_intel\observables.py"
        "threat_intel_parameter_store.py"   = Join-Path $NativeRoot "threat_intel\parameter_store.py"
        "threat_intel_cache.py"             = Join-Path $NativeRoot "threat_intel\cache.py"
        "threat_intel_provider_result.py"   = Join-Path $NativeRoot "threat_intel\provider_result.py"
        "threat_intel_http_client.py"       = Join-Path $NativeRoot "threat_intel\http_client.py"
        "threat_intel_greynoise.py"         = Join-Path $NativeRoot "threat_intel\greynoise.py"
        "threat_intel_virustotal.py"        = Join-Path $NativeRoot "threat_intel\virustotal.py"
        "threat_intel_shodan.py"            = Join-Path $NativeRoot "threat_intel\shodan.py"
        "threat_intel_broker.py"            = Join-Path $NativeRoot "threat_intel\broker.py"
        "threat_intel_rate_governor.py"     = Join-Path $NativeRoot "threat_intel\rate_governor.py"
        "threat_intel_worker.py"            = Join-Path $NativeRoot "threat_intel\worker.py"
    }
}

function Get-FirewallAssetMap {
    return [ordered]@{
        "patriotpot-egress-firewall.sh" = Join-Path $NativeRoot "patriotpot-egress-firewall.sh"
        "patriotpot-egress-firewall.service" = Join-Path $NativeRoot "patriotpot-egress-firewall.service"
    }
}

function Assert-AssetIntegrity {
    $assets = Get-AssetMap
    $missing = @($assets.GetEnumerator() | Where-Object { -not (Test-Path -LiteralPath $_.Value) })
    if ($missing.Count -gt 0) {
        throw "Missing deployment assets: $($missing.Name -join ', ')"
    }

    $secretPatterns = @(
        "-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----\s*\r?\n[A-Za-z0-9+/]{40}",
        "https://(?:discord(?:app)?\.com)/api/webhooks/",
        "\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    )
    foreach ($asset in $assets.GetEnumerator()) {
        $content = Get-Content -LiteralPath $asset.Value -Raw
        foreach ($pattern in $secretPatterns) {
            if ($content -match $pattern) {
                throw "Secret-pattern preflight failed for deployment asset $($asset.Name)."
            }
        }
    }

    $bootstrap = Join-Path $NativeRoot "bootstrap-native.sh"
    $bootstrapContent = Get-Content -LiteralPath $bootstrap -Raw
    foreach ($asset in $assets.GetEnumerator()) {
        $expected = Get-Sha256 $asset.Value
        $escapedName = [regex]::Escape($asset.Name)
        if ($bootstrapContent -notmatch "(?m)^$expected  $escapedName`r?$") {
            throw "Bootstrap hash pin is stale or absent for $($asset.Name)."
        }
    }

    $templateContent = Get-Content -LiteralPath $Template -Raw
    foreach ($forbidden in @(
        "AWS::EC2::SecurityGroupIngress",
        "ContainerImageUri",
        "docker run",
        "containerd",
        "podman",
        "ecs:"
    )) {
        if ($templateContent -match [regex]::Escape($forbidden)) {
            throw "Forbidden deployment declaration found in template: $forbidden"
        }
    }
    # Exposure Gate E1 (LIVE CONTROL): the template now declares exactly one
    # inbound rule, TCP/2222 from 0.0.0.0/0, for the Cowrie listener. This
    # mirrors validate-native-baseline.py's identical, already-reviewed
    # E1.1 fix. TCP/22, TCP/2223, and TCP/UDP 111 remain hard-prohibited
    # everywhere in the template.
    $ingressOccurrences = ([regex]::Matches($templateContent, "SecurityGroupIngress:")).Count
    if ($ingressOccurrences -ne 1) {
        throw "Template must declare exactly one SecurityGroupIngress block (found $ingressOccurrences)."
    }
    $ingressStart = $templateContent.IndexOf("SecurityGroupIngress:")
    $egressStart = $templateContent.IndexOf("SecurityGroupEgress:", $ingressStart)
    if ($egressStart -lt 0) {
        throw "Malformed template: SecurityGroupEgress not found after SecurityGroupIngress."
    }
    $ingressBlock = $templateContent.Substring($ingressStart, $egressStart - $ingressStart)
    if ($ingressBlock -notmatch "IpProtocol: tcp" -or
        $ingressBlock -notmatch "FromPort: 2222" -or
        $ingressBlock -notmatch "ToPort: 2222" -or
        $ingressBlock -notmatch "CidrIp: 0\.0\.0\.0/0") {
        throw "SecurityGroupIngress must expose exactly TCP/2222 from 0.0.0.0/0 (Exposure Gate E1)."
    }
    if (([regex]::Matches($ingressBlock, "IpProtocol:")).Count -ne 1) {
        throw "SecurityGroupIngress must declare exactly one rule."
    }
    if ($ingressBlock -match "CidrIpv6") {
        throw "SecurityGroupIngress must not declare IPv6 ingress."
    }
    if ($templateContent -match "(?m)^\s*(FromPort|ToPort):\s*(22|2223|111)\s*$") {
        throw "Prohibited inbound port declaration found in template."
    }
}

function Resolve-OfficialAl2Ami {
    $parameterName = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    $parameter = Invoke-Aws ssm get-parameter `
        --name $parameterName `
        --output json | ConvertFrom-Json
    $amiId = $parameter.Parameter.Value
    if ($amiId -notmatch "^ami-[0-9a-f]+$") {
        throw "Official AL2 public parameter did not return an AMI ID."
    }
    $image = Invoke-Aws ec2 describe-images `
        --image-ids $amiId `
        --owners 137112412989 `
        --output json | ConvertFrom-Json
    if ($image.Images.Count -ne 1) {
        throw "DEPLOYMENT_PREFLIGHT_AL2_LOOKUP: expected exactly one official Amazon Linux 2 image."
    }
    $candidate = $image.Images[0]
    $valid = (
        $candidate.OwnerId -eq "137112412989" -and
        $candidate.ImageOwnerAlias -eq "amazon" -and
        $candidate.Architecture -eq "x86_64" -and
        $candidate.VirtualizationType -eq "hvm" -and
        $candidate.RootDeviceType -eq "ebs" -and
        $candidate.State -eq "available" -and
        $candidate.Name -match "^amzn2-ami-hvm-"
    )
    if (-not $valid) {
        throw "DEPLOYMENT_PREFLIGHT_AL2_METADATA: resolved image failed required owner/platform metadata checks."
    }
    return $candidate
}

function Get-HostKeyMetadata {
    $description = Invoke-Aws secretsmanager describe-secret `
        --secret-id $SecretName `
        --output json | ConvertFrom-Json
    $versions = Invoke-Aws secretsmanager list-secret-version-ids `
        --secret-id $SecretName `
        --include-deprecated `
        --output json | ConvertFrom-Json
    $current = @($versions.Versions | Where-Object { $_.VersionStages -contains "AWSCURRENT" })
    if ($current.Count -ne 1) {
        throw "Cowrie host-key secret does not have exactly one AWSCURRENT version."
    }

    # Deployment reconciliation uses metadata only. Secret material is never
    # retrieved by the workstation orchestrator.
    return [pscustomobject]@{
        Arn = $description.ARN
        VersionId = $current[0].VersionId
        CreatedDate = $current[0].CreatedDate
        VersionCount = $versions.Versions.Count
    }
}

function Publish-Asset([string]$Bucket, [string]$Key, [string]$Path, [string]$Hash) {
    $putOutput = aws s3api put-object `
        --bucket $Bucket `
        --key $Key `
        --body $Path `
        --metadata "sha256=$Hash" `
        --server-side-encryption AES256 `
        --if-none-match "*" `
        --output json `
        --profile patriotpot `
        --region us-east-1 2>&1
    $putExit = $LASTEXITCODE
    if ($putExit -ne 0) {
        $putError = ($putOutput | Out-String)
        if ($putError -notmatch "(?i)(PreconditionFailed|\b412\b)") {
            throw "Atomic S3 bundle create failed for $Key."
        }
    }
    $verified = Invoke-Aws s3api head-object `
        --bucket $Bucket `
        --key $Key `
        --output json | ConvertFrom-Json
    if ($verified.Metadata.sha256 -ne $Hash) {
        throw "Content-address collision or S3 verification failure for $Key"
    }
}

function Publish-BootstrapBundle([string]$Bucket) {
    $bootstrap = Join-Path $NativeRoot "bootstrap-native.sh"
    $bootstrapHash = Get-Sha256 $bootstrap
    $bundleId = $bootstrapHash
    $prefix = "bootstrap/$bundleId"
    Publish-Asset $Bucket "$prefix/bootstrap-native.sh" $bootstrap $bootstrapHash
    foreach ($asset in (Get-AssetMap).GetEnumerator()) {
        $hash = Get-Sha256 $asset.Value
        Publish-Asset $Bucket "$prefix/$($asset.Name)" $asset.Value $hash
    }
    return [pscustomobject]@{
        BundleId = $bundleId
        BootstrapSha256 = $bootstrapHash
        Prefix = $prefix
        AssetCount = (Get-AssetMap).Count + 1
    }
}

function New-ReviewedChangeSet(
    [string]$AmiId,
    [object]$HostKey,
    [object]$Bundle,
    [bool]$RequireInstanceReplacement
) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $name = "native-al2-remediation-$timestamp"
    $firewallAssets = Get-FirewallAssetMap
    $parameters = @(
        "ParameterKey=HostAmiId,ParameterValue=$AmiId",
        "ParameterKey=BootstrapBundleId,ParameterValue=$($Bundle.BundleId)",
        "ParameterKey=BootstrapScriptSha256,ParameterValue=$($Bundle.BootstrapSha256)",
        "ParameterKey=FirewallBundleId,ParameterValue=$($Bundle.BundleId)",
        "ParameterKey=FirewallScriptSha256,ParameterValue=$(Get-Sha256 $firewallAssets['patriotpot-egress-firewall.sh'])",
        "ParameterKey=FirewallUnitSha256,ParameterValue=$(Get-Sha256 $firewallAssets['patriotpot-egress-firewall.service'])",
        "ParameterKey=DiscordMonitorSha256,ParameterValue=$(Get-Sha256 (Join-Path $NativeRoot 'discord-monitor.py'))",
        "ParameterKey=CowrieHostKeySecret,ParameterValue=$($HostKey.Arn)",
        "ParameterKey=CowrieHostKeyVersionId,ParameterValue=$($HostKey.VersionId)",
        "ParameterKey=DiscordWebhookParameterName,ParameterValue=$DiscordWebhookParameterName",
        "ParameterKey=InstanceType,UsePreviousValue=true",
        "ParameterKey=Environment,UsePreviousValue=true"
    )
    $response = Invoke-Aws cloudformation create-change-set `
        --stack-name $StackName `
        --change-set-name $name `
        --change-set-type UPDATE `
        --description "patriotpot-2026-control-pre-exposure-20260915 native AL2 remediation" `
        --template-body "file://$Template" `
        --parameters $parameters `
        --capabilities CAPABILITY_NAMED_IAM `
        --include-nested-stacks `
        --output json | ConvertFrom-Json

    Invoke-Aws cloudformation wait change-set-create-complete `
        --stack-name $StackName `
        --change-set-name $response.Id
    $review = Invoke-Aws cloudformation describe-change-set `
        --stack-name $StackName `
        --change-set-name $response.Id `
        --include-property-values `
        --output json | ConvertFrom-Json

    $replacementChanges = @(
        $review.Changes |
            Where-Object {
                $_.ResourceChange.PSObject.Properties.Name -contains "Replacement" -and
                $_.ResourceChange.Replacement -in @("True", "Conditional")
            }
    )
    if ($RequireInstanceReplacement) {
        $unexpectedReplacement = @(
            $replacementChanges |
                Where-Object { $_.ResourceChange.LogicalResourceId -ne "PatriotPotInstanceV2" }
        )
    } else {
        $unexpectedReplacement = @(
            $replacementChanges |
                Where-Object {
                    $_.ResourceChange.LogicalResourceId -ne "PatriotPotInstanceV2" -or
                    $_.ResourceChange.Replacement -eq "True"
                }
        )
    }
    if ($unexpectedReplacement.Count -gt 0) {
        throw "Change set contains an unexpected replacement: $($unexpectedReplacement.ResourceChange.LogicalResourceId -join ', ')"
    }
    $instanceReplacement = @(
        $review.Changes |
            Where-Object {
                $_.ResourceChange.LogicalResourceId -eq "PatriotPotInstanceV2" -and
                $_.ResourceChange.Replacement -eq "True"
            }
    )
    if ($RequireInstanceReplacement -and $instanceReplacement.Count -ne 1) {
        throw "Change set does not contain the required EC2 instance replacement."
    }
    if (-not $RequireInstanceReplacement -and $instanceReplacement.Count -ne 0) {
        throw "Change set unexpectedly replaces an instance already on the pinned AMI."
    }
    $eipReplacement = @(
        $review.Changes |
            Where-Object {
                $_.ResourceChange.LogicalResourceId -eq "PatriotPotEIP" -and
                $_.ResourceChange.PSObject.Properties.Name -contains "Replacement" -and
                $_.ResourceChange.Replacement -in @("True", "Conditional")
            }
    )
    if ($eipReplacement.Count -gt 0) {
        throw "Change set would replace the preserved Elastic IP."
    }
    return [pscustomobject]@{
        Id = $response.Id
        Name = $name
        Review = $review
    }
}

function New-FirewallOnlyChangeSet([object]$Bundle) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $name = "egress-firewall-$timestamp"
    $firewallAssets = Get-FirewallAssetMap
    $parameters = @(
        "ParameterKey=HostAmiId,UsePreviousValue=true",
        "ParameterKey=BootstrapBundleId,UsePreviousValue=true",
        "ParameterKey=BootstrapScriptSha256,UsePreviousValue=true",
        "ParameterKey=FirewallBundleId,ParameterValue=$($Bundle.BundleId)",
        "ParameterKey=FirewallScriptSha256,ParameterValue=$(Get-Sha256 $firewallAssets['patriotpot-egress-firewall.sh'])",
        "ParameterKey=FirewallUnitSha256,ParameterValue=$(Get-Sha256 $firewallAssets['patriotpot-egress-firewall.service'])",
        "ParameterKey=DiscordMonitorSha256,ParameterValue=$(Get-Sha256 (Join-Path $NativeRoot 'discord-monitor.py'))",
        "ParameterKey=CowrieHostKeySecret,UsePreviousValue=true",
        "ParameterKey=CowrieHostKeyVersionId,UsePreviousValue=true",
        "ParameterKey=DiscordWebhookParameterName,UsePreviousValue=true",
        "ParameterKey=InstanceType,UsePreviousValue=true",
        "ParameterKey=Environment,UsePreviousValue=true"
    )
    $response = Invoke-Aws cloudformation create-change-set `
        --stack-name $StackName `
        --change-set-name $name `
        --change-set-type UPDATE `
        --description "patriotpot-2026-control-pre-exposure-20260915 minimal egress firewall" `
        --template-body "file://$Template" `
        --parameters $parameters `
        --capabilities CAPABILITY_NAMED_IAM `
        --include-nested-stacks `
        --output json | ConvertFrom-Json

    Invoke-Aws cloudformation wait change-set-create-complete `
        --stack-name $StackName `
        --change-set-name $response.Id
    $review = Invoke-Aws cloudformation describe-change-set `
        --stack-name $StackName `
        --change-set-name $response.Id `
        --include-property-values `
        --output json | ConvertFrom-Json
    $replacements = @(
        $review.Changes |
            Where-Object {
                $_.ResourceChange.PSObject.Properties.Name -contains "Replacement" -and
                $_.ResourceChange.Replacement -in @("True", "Conditional")
            }
    )
    if ($replacements.Count -gt 0) {
        throw "Firewall-only change set contains forbidden replacement: $($replacements.ResourceChange.LogicalResourceId -join ', ')"
    }
    $forbiddenChanges = @(
        $review.Changes |
            Where-Object {
                $_.ResourceChange.LogicalResourceId -in @("PatriotPotInstanceV2", "PatriotPotEIP")
            }
    )
    if ($forbiddenChanges.Count -gt 0) {
        throw "Firewall-only change set changes protected resource(s): $($forbiddenChanges.ResourceChange.LogicalResourceId -join ', ')"
    }
    $actual = @($review.Changes.ResourceChange.LogicalResourceId)
    foreach ($required in @(
        "PatriotPotDiscordMonitorAssociation",
        "PatriotPotInstanceRole"
    )) {
        if ($actual -notcontains $required) {
            throw "Firewall-only change set lacks required resource update: $required"
        }
    }
    return [pscustomobject]@{
        Id = $response.Id
        Name = $name
        Review = $review
    }
}

function Test-ChangeIsHashSubstitutionOnly([object]$ResourceChange) {
    # True only if every property-value diff on this resource differs *solely*
    # in embedded 64-hex-char strings (content-address hashes / bundle IDs) --
    # e.g. an association's command text moving to a new bundle path prefix
    # with byte-identical script logic. Never true for EvidenceBucketPolicy,
    # which has no embedded hashes; that resource is checked separately by
    # Test-EvidenceBucketPolicyChangeIsDependencyOnly.
    $details = @($ResourceChange.Details)
    if ($details.Count -eq 0) {
        return $false
    }
    foreach ($detail in $details) {
        if (-not ($detail.PSObject.Properties.Name -contains "BeforeValue") -or
            -not ($detail.PSObject.Properties.Name -contains "AfterValue")) {
            return $false
        }
        $normalizedBefore = [regex]::Replace($detail.BeforeValue, "[0-9a-f]{64}", "<HASH>")
        $normalizedAfter = [regex]::Replace($detail.AfterValue, "[0-9a-f]{64}", "<HASH>")
        if ($normalizedBefore -ne $normalizedAfter) {
            return $false
        }
    }
    return $true
}

function Test-EvidenceBucketPolicyChangeIsDependencyOnly([object]$ResourceChange) {
    # H1 finding: this resource can appear as Modify purely because it
    # references !GetAtt PatriotPotInstanceRole.Arn and that role is also
    # being modified -- CloudFormation's conservative dependency
    # propagation, not an actual policy-document edit. Every Details[]
    # entry must be Evaluation=Dynamic; a real content change would show
    # Evaluation=Static with ChangeSource=DirectModification instead.
    $details = @($ResourceChange.Details)
    if ($details.Count -eq 0) {
        return $false
    }
    foreach ($detail in $details) {
        if ($detail.Evaluation -ne "Dynamic") {
            return $false
        }
    }
    return $true
}

function New-H2ChangeSet([object]$Bundle) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $name = "h2-threat-intel-$timestamp"
    $parameters = @(
        "ParameterKey=HostAmiId,UsePreviousValue=true",
        "ParameterKey=BootstrapBundleId,UsePreviousValue=true",
        "ParameterKey=BootstrapScriptSha256,UsePreviousValue=true",
        "ParameterKey=FirewallBundleId,ParameterValue=$($Bundle.BundleId)",
        "ParameterKey=FirewallScriptSha256,ParameterValue=$(Get-Sha256 (Join-Path $NativeRoot 'patriotpot-egress-firewall.sh'))",
        "ParameterKey=FirewallUnitSha256,ParameterValue=$(Get-Sha256 (Join-Path $NativeRoot 'patriotpot-egress-firewall.service'))",
        "ParameterKey=DiscordMonitorSha256,ParameterValue=$(Get-Sha256 (Join-Path $NativeRoot 'discord-monitor.py'))",
        "ParameterKey=CowrieHostKeySecret,UsePreviousValue=true",
        "ParameterKey=CowrieHostKeyVersionId,UsePreviousValue=true",
        "ParameterKey=DiscordWebhookParameterName,UsePreviousValue=true",
        "ParameterKey=InstanceType,UsePreviousValue=true",
        "ParameterKey=Environment,UsePreviousValue=true"
    )
    $response = Invoke-Aws cloudformation create-change-set `
        --stack-name $StackName `
        --change-set-name $name `
        --change-set-type UPDATE `
        --description "H2 threat-intelligence enrichment and session clustering" `
        --template-body "file://$Template" `
        --parameters $parameters `
        --capabilities CAPABILITY_NAMED_IAM `
        --include-nested-stacks `
        --output json | ConvertFrom-Json

    Invoke-Aws cloudformation wait change-set-create-complete `
        --stack-name $StackName `
        --change-set-name $response.Id
    $review = Invoke-Aws cloudformation describe-change-set `
        --stack-name $StackName `
        --change-set-name $response.Id `
        --include-property-values `
        --output json | ConvertFrom-Json
    # H1 finding: --include-property-values can silently omit a Dynamic-only
    # change (e.g. EvidenceBucketPolicy). The allowlist below is evaluated
    # against the plain (no property-values) listing, which is authoritative
    # for "which resources changed at all".
    $plainReview = Invoke-Aws cloudformation describe-change-set `
        --stack-name $StackName `
        --change-set-name $response.Id `
        --output json | ConvertFrom-Json

    $replacements = @(
        $plainReview.Changes |
            Where-Object {
                $_.ResourceChange.PSObject.Properties.Name -contains "Replacement" -and
                $_.ResourceChange.Replacement -in @("True", "Conditional")
            }
    )
    if ($replacements.Count -gt 0) {
        throw "H2 change set contains a forbidden replacement: $($replacements.ResourceChange.LogicalResourceId -join ', ')"
    }

    $requiredResources = @("PatriotPotDiscordMonitorAssociation", "PatriotPotInstanceRole")
    $conditionallyAllowed = @("EvidenceBucketPolicy", "PatriotPotEgressFirewallAssociation")
    $actualResources = @($plainReview.Changes.ResourceChange.LogicalResourceId)

    foreach ($required in $requiredResources) {
        if ($actualResources -notcontains $required) {
            throw "H2 change set lacks required resource update: $required"
        }
    }

    $unexpected = @($actualResources | Where-Object { ($requiredResources + $conditionallyAllowed) -notcontains $_ })
    if ($unexpected.Count -gt 0) {
        throw "H2 change set contains resource(s) outside the allowlist: $($unexpected -join ', ')"
    }

    # explicit hard-fail even if somehow present under a different guise
    foreach ($protected in @(
        "PatriotPotInstanceV2", "PatriotPotEIP", "PatriotPotSecurityGroup",
        "VPC", "PublicSubnet", "PublicRouteTable", "PublicRoute",
        "SubnetRouteTableAssociation", "InternetGateway", "AttachGateway"
    )) {
        if ($actualResources -contains $protected) {
            throw "H2 change set unexpectedly touches protected resource: $protected"
        }
    }

    if ($actualResources -contains "EvidenceBucketPolicy") {
        $bucketPolicyChange = ($plainReview.Changes | Where-Object { $_.ResourceChange.LogicalResourceId -eq "EvidenceBucketPolicy" }).ResourceChange
        if (-not (Test-EvidenceBucketPolicyChangeIsDependencyOnly $bucketPolicyChange)) {
            throw "H2 change set modifies EvidenceBucketPolicy with a non-dependency-only change; this requires separate review."
        }
    }

    if ($actualResources -contains "PatriotPotEgressFirewallAssociation") {
        $firewallAssocChange = ($plainReview.Changes | Where-Object { $_.ResourceChange.LogicalResourceId -eq "PatriotPotEgressFirewallAssociation" }).ResourceChange
        if (-not (Test-ChangeIsHashSubstitutionOnly $firewallAssocChange)) {
            throw "H2 change set modifies PatriotPotEgressFirewallAssociation beyond a bundle-path hash substitution; this requires separate review."
        }
    }

    return [pscustomobject]@{
        Id = $response.Id
        Name = $name
        Review = $review
        PlainReview = $plainReview
    }
}

Set-Location $ProjectRoot

Section "PREFLIGHT"
if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    throw "AWS CLI not found."
}
if (-not (Test-Path -LiteralPath $Template)) {
    throw "CloudFormation template not found: $Template"
}
Assert-AssetIntegrity
$null = Invoke-Aws sts get-caller-identity --output json
$null = Invoke-Aws cloudformation validate-template --template-body "file://$Template"

if ($FirewallOnly) {
    $stack = Invoke-Aws cloudformation describe-stacks `
        --stack-name $StackName `
        --output json | ConvertFrom-Json
    $EvidenceBucket = (
        $stack.Stacks[0].Outputs |
        Where-Object OutputKey -eq "EvidenceBucketName"
    ).OutputValue
    if (-not $EvidenceBucket) {
        throw "Existing evidence bucket output was not found."
    }
    $currentInstanceId = (
        Invoke-Aws cloudformation describe-stack-resource `
            --stack-name $StackName `
            --logical-resource-id PatriotPotInstanceV2 `
            --output json | ConvertFrom-Json
    ).StackResourceDetail.PhysicalResourceId
    if ([string]::IsNullOrWhiteSpace($currentInstanceId)) {
        throw "Existing native instance ID was not found."
    }
    Write-Host "Minimal control remediation preflight PASS"
    Write-Host "Cowrie host key and Discord credential: not accessed"
    Write-Host "Existing instance: $currentInstanceId (protected from replacement)"
    Write-Host "Template ingress declaration: none"

    if ($PreflightOnly) {
        return
    }

    Section "PUBLISH CONTENT-ADDRESSED MINIMAL CONTROL BUNDLE"
    # Publishing the complete native asset map preserves its established
    # bundle manifest; the firewall association retrieves only its two
    # independently SHA-256-verified files.
    $bundle = Publish-BootstrapBundle $EvidenceBucket
    Write-Host "Bundle: $($bundle.BundleId)"
    Write-Host "Assets: $($bundle.AssetCount)"

    Section "CREATE AND REVIEW MINIMAL CONTROL CLOUDFORMATION CHANGE SET"
    $changeSet = New-FirewallOnlyChangeSet $bundle
    Write-Host "Change set: $($changeSet.Id)"
    $changeSet.Review.Changes | ForEach-Object {
        $change = $_.ResourceChange
        $replacement = if ($change.PSObject.Properties.Name -contains "Replacement") {
            $change.Replacement
        } else {
            "N/A"
        }
        Write-Host (
            "{0,-35} action={1,-8} replacement={2}" -f
            $change.LogicalResourceId,
            $change.Action,
            $replacement
        )
    }

    if (-not $ExecuteChangeSet) {
        Write-Host "Change set passed no-replacement and protected-resource guards; not executed."
        return
    }

    Section "EXECUTE REVIEWED MINIMAL CONTROL CHANGE SET"
    Invoke-Aws cloudformation execute-change-set `
        --stack-name $StackName `
        --change-set-name $changeSet.Id
    Invoke-Aws cloudformation wait stack-update-complete --stack-name $StackName
    $final = Invoke-Aws cloudformation describe-stacks `
        --stack-name $StackName `
        --output json | ConvertFrom-Json
    Write-Host "Final stack status: $($final.Stacks[0].StackStatus)"
    Write-Host "Firewall and Discord monitor associations are CloudFormation-managed; runtime validation remains required."
    return
}

if ($H2) {
    $stack = Invoke-Aws cloudformation describe-stacks `
        --stack-name $StackName `
        --output json | ConvertFrom-Json
    $EvidenceBucket = (
        $stack.Stacks[0].Outputs |
        Where-Object OutputKey -eq "EvidenceBucketName"
    ).OutputValue
    if (-not $EvidenceBucket) {
        throw "Existing evidence bucket output was not found."
    }
    $currentInstanceId = (
        Invoke-Aws cloudformation describe-stack-resource `
            --stack-name $StackName `
            --logical-resource-id PatriotPotInstanceV2 `
            --output json | ConvertFrom-Json
    ).StackResourceDetail.PhysicalResourceId
    if ([string]::IsNullOrWhiteSpace($currentInstanceId)) {
        throw "Existing native instance ID was not found."
    }
    Write-Host "H2 threat-intelligence preflight PASS"
    Write-Host "Cowrie host key and Discord credential: not accessed"
    Write-Host "Existing instance: $currentInstanceId (protected from replacement)"
    Write-Host "Template ingress declaration: unchanged (TCP/2222 only)"

    if ($PreflightOnly) {
        return
    }

    Section "PUBLISH CONTENT-ADDRESSED H2 SUPPORT BUNDLE"
    $bundle = Publish-BootstrapBundle $EvidenceBucket
    Write-Host "Bundle: $($bundle.BundleId)"
    Write-Host "Assets: $($bundle.AssetCount)"

    Section "CREATE AND REVIEW H2 CLOUDFORMATION CHANGE SET"
    $changeSet = New-H2ChangeSet $bundle
    Write-Host "Change set: $($changeSet.Id)"
    Write-Host "Resource inventory (authoritative, no --include-property-values):"
    $changeSet.PlainReview.Changes | ForEach-Object {
        $change = $_.ResourceChange
        $replacement = if ($change.PSObject.Properties.Name -contains "Replacement") {
            $change.Replacement
        } else {
            "N/A"
        }
        Write-Host (
            "{0,-40} action={1,-8} replacement={2}" -f
            $change.LogicalResourceId,
            $change.Action,
            $replacement
        )
    }

    if (-not $ExecuteChangeSet) {
        Write-Host "Change set passed the H2 allowlist guard (no replacement, no resource outside PatriotPotDiscordMonitorAssociation / PatriotPotInstanceRole / conditionally-verified EvidenceBucketPolicy / PatriotPotEgressFirewallAssociation); not executed."
        return
    }

    Section "EXECUTE REVIEWED H2 CHANGE SET"
    Invoke-Aws cloudformation execute-change-set `
        --stack-name $StackName `
        --change-set-name $changeSet.Id
    Invoke-Aws cloudformation wait stack-update-complete --stack-name $StackName
    $final = Invoke-Aws cloudformation describe-stacks `
        --stack-name $StackName `
        --output json | ConvertFrom-Json
    Write-Host "Final stack status: $($final.Stacks[0].StackStatus)"
    Write-Host "Threat-intelligence enrichment is now CloudFormation-managed; runtime validation remains required."
    return
}

$ami = Resolve-OfficialAl2Ami
$hostKey = Get-HostKeyMetadata

$stack = Invoke-Aws cloudformation describe-stacks `
    --stack-name $StackName `
    --output json | ConvertFrom-Json
$EvidenceBucket = (
    $stack.Stacks[0].Outputs |
    Where-Object OutputKey -eq "EvidenceBucketName"
).OutputValue
if (-not $EvidenceBucket) {
    throw "Existing evidence bucket output was not found."
}
$currentBundleId = (
    $stack.Stacks[0].Parameters |
    Where-Object ParameterKey -eq "BootstrapBundleId"
).ParameterValue
if ([string]::IsNullOrWhiteSpace($currentBundleId)) {
    throw "Existing bootstrap bundle parameter was not found."
}
$desiredBundleId = Get-Sha256 (Join-Path $NativeRoot "bootstrap-native.sh")
$currentInstanceId = (
    Invoke-Aws cloudformation describe-stack-resource `
        --stack-name $StackName `
        --logical-resource-id PatriotPotInstanceV2 `
        --output json | ConvertFrom-Json
).StackResourceDetail.PhysicalResourceId
$currentImageId = (
    Invoke-Aws ec2 describe-instances `
        --instance-ids $currentInstanceId `
        --query "Reservations[0].Instances[0].ImageId" `
        --output text
)
# UserData updates on an existing EC2 instance do not execute the new native
# bundle. The template therefore ties its replacement-only primary ENI
# description to BootstrapBundleId, and this guard makes absence of that
# replacement a hard failure during change-set review.
$requireInstanceReplacement = (
    $currentImageId -ne $ami.ImageId -or
    $currentBundleId -ne $desiredBundleId
)

Write-Host "Preflight PASS"
Write-Host "AMI: $($ami.ImageId) owner=$($ami.OwnerId) alias=$($ami.ImageOwnerAlias) name=$($ami.Name)"
Write-Host "Current bootstrap bundle: $currentBundleId"
Write-Host "Desired bootstrap bundle: $desiredBundleId"
Write-Host "Cowrie host-key version: $($hostKey.VersionId)"
Write-Host "Cowrie host-key material: not retrieved (metadata-only reconciliation)"
Write-Host "Template ingress declaration: none"
Write-Host "Container runtime declaration: none"
Write-Host "Instance replacement required: $requireInstanceReplacement"

if ($PreflightOnly) {
    return
}

Section "PUBLISH CONTENT-ADDRESSED NATIVE ASSETS"
$bundle = Publish-BootstrapBundle $EvidenceBucket
Write-Host "Bundle: $($bundle.BundleId)"
Write-Host "Assets: $($bundle.AssetCount)"

Section "CREATE AND REVIEW CLOUDFORMATION CHANGE SET"
$changeSet = New-ReviewedChangeSet $ami.ImageId $hostKey $bundle $requireInstanceReplacement
Write-Host "Change set: $($changeSet.Id)"
$changeSet.Review.Changes | ForEach-Object {
    $change = $_.ResourceChange
    $replacement = if ($change.PSObject.Properties.Name -contains "Replacement") {
        $change.Replacement
    } else {
        "N/A"
    }
    Write-Host (
        "{0,-35} action={1,-8} replacement={2}" -f
        $change.LogicalResourceId,
        $change.Action,
        $replacement
    )
}

if (-not $ExecuteChangeSet) {
    Write-Host ""
    Write-Host "Change set passed automated replacement guards and is NOT executed."
    Write-Host "Re-run with -ExecuteChangeSet after reviewing the displayed changes."
    return
}

Section "EXECUTE REVIEWED CHANGE SET"
Invoke-Aws cloudformation execute-change-set `
    --stack-name $StackName `
    --change-set-name $changeSet.Id
Invoke-Aws cloudformation wait stack-update-complete --stack-name $StackName
$final = Invoke-Aws cloudformation describe-stacks `
    --stack-name $StackName `
    --output json | ConvertFrom-Json
Write-Host "Final stack status: $($final.Stacks[0].StackStatus)"
Write-Host "Deployment complete. Perform fresh SSM/runtime validation before claiming success."
