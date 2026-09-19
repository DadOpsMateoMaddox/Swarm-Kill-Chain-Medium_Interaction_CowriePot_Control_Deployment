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
    [switch]$AuthParity,
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

function Get-AuthParityAssetMap {
    # Single-file bundle, deliberately separate from Get-AssetMap /
    # Get-FirewallAssetMap: this gate must never share a content address
    # with H1's firewall or H2's discord-monitor assets (evidence/
    # AUTH-PARITY-GATE.md section 8, "why a dedicated bundle").
    return [ordered]@{
        "userdb.txt" = Join-Path $ProjectRoot "userdb.txt"
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

function Publish-AuthParityBundle([string]$Bucket) {
    $assets = Get-AuthParityAssetMap
    $userdbPath = $assets["userdb.txt"]
    $userdbHash = Get-Sha256 $userdbPath
    $bundleId = $userdbHash
    $prefix = "bootstrap/$bundleId"
    Publish-Asset $Bucket "$prefix/userdb.txt" $userdbPath $userdbHash
    return [pscustomobject]@{
        BundleId = $bundleId
        UserdbSha256 = $userdbHash
        Prefix = $prefix
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

function Get-TemplateParameterNames([string]$TemplatePath) {
    # Text-level extraction, matching this file's existing style (see
    # Assert-AssetIntegrity's ingress-block checks) rather than a full YAML
    # parse. Bounded strictly between the top-level Parameters: and
    # Resources: keys so a resource whose name happens to match the same
    # 2-space-indent-then-colon shape is never picked up. Takes an explicit
    # path rather than always reading the script-scope $Template, so it can
    # be run against a template snapshot as well as the working template.
    $templateContent = (Get-Content -LiteralPath $TemplatePath -Raw) -replace "`r`n", "`n"
    $parametersStart = $templateContent.IndexOf("`nParameters:")
    $resourcesStart = $templateContent.IndexOf("`nResources:")
    if ($parametersStart -lt 0 -or $resourcesStart -lt 0 -or $resourcesStart -le $parametersStart) {
        throw "Could not locate a Parameters: block before Resources: in the template."
    }
    $parametersBlock = $templateContent.Substring($parametersStart, $resourcesStart - $parametersStart)
    $names = [regex]::Matches($parametersBlock, "(?m)^  ([A-Za-z][A-Za-z0-9]*):\s*$") |
        ForEach-Object { $_.Groups[1].Value }
    return @($names)
}

function Get-DeployedTemplateText {
    # Authoritative base for the auth-parity template snapshot: the exact
    # template CloudFormation currently has associated with the live stack,
    # not this working tree's file (which may carry undeployed H2 edits).
    $response = Invoke-Aws cloudformation get-template `
        --stack-name $StackName `
        --output json | ConvertFrom-Json
    return $response.TemplateBody
}

function Add-AuthParityTemplatePatch([string]$BaseTemplateText) {
    # Replays exactly the reviewed auth-parity template diff (evidence/
    # AUTH-PARITY-GATE.md section 8: 2 Parameters, 1 IAM ARN line, 1 new
    # Association resource) onto a clean base, instead of using this
    # working tree's H2-mixed file directly. Each anchor must occur exactly
    # once in the base text; anything else -- a base that doesn't look like
    # what this patch expects -- is a fail-closed error, not a best-effort
    # insertion.
    $text = $BaseTemplateText -replace "`r`n", "`n"

    $paramAnchor = "  DiscordMonitorSha256:`n    Type: String`n    AllowedPattern: '^[0-9a-f]{64}`$'`n    Description: SHA-256 for the direct public-HTTPS Discord monitor in FirewallBundleId`n"
    $paramInsert = @"

  AuthParityBundleId:
    Type: String
    AllowedPattern: '^[0-9a-f]{64}`$'
    Description: >
      Content-addressed bundle supplying only the auth-parity-corrected
      userdb.txt. Intentionally distinct from FirewallBundleId so this
      Control-parity correction stays reviewable and revertible independent
      of H2 or the egress firewall, and so the current instance is not
      replaced to apply it.

  UserdbTxtSha256:
    Type: String
    AllowedPattern: '^[0-9a-f]{64}`$'
    Description: SHA-256 for the corrected userdb.txt in AuthParityBundleId

"@
    $text = Set-AnchoredInsertion $text $paramAnchor ($paramAnchor + $paramInsert) "Parameters (AuthParityBundleId/UserdbTxtSha256)"

    $iamAnchor = "                  - !Sub '`${EvidenceBucket.Arn}/bootstrap/`${FirewallBundleId}/discord-monitor.py'`n"
    $iamInsert = "                  - !Sub '`${EvidenceBucket.Arn}/bootstrap/`${AuthParityBundleId}/userdb.txt'`n"
    $text = Set-AnchoredInsertion $text $iamAnchor ($iamAnchor + $iamInsert) "PatriotPotBootstrapRead explicit ARN list"

    $assocAnchor = "              systemctl try-restart patriotpot-discord.service`n              systemctl is-active --quiet patriotpot-discord.service`n"
    $assocInsert = @"

  # Control-parity correction (auth semantics only). Deliberately isolated
  # from PatriotPotDiscordMonitorAssociation and PatriotPotEgressFirewallAssociation:
  # its own content-addressed bundle (AuthParityBundleId), its own IAM read
  # grant, its own restart scope (cowrie.service only -- discord-monitor and
  # the egress firewall are untouched by this association). This corrects
  # userdb.txt to match the reconstructed 2025 steady-state authentication
  # surface; it carries no telemetry, presentation, or enrichment changes.
  PatriotPotAuthParityAssociation:
    Type: AWS::SSM::Association
    DependsOn:
      - PatriotPotInstanceV2
      - PatriotPotInstanceRole
    Properties:
      AssociationName: !Sub '`${AWS::StackName}-auth-parity'
      Name: AWS-RunShellScript
      Targets:
        - Key: InstanceIds
          Values:
            - !Ref PatriotPotInstanceV2
      WaitForSuccessTimeoutSeconds: 600
      Parameters:
        commands:
          - !Sub |
              set -euo pipefail
              echo "AUTH_PARITY_T_PRE=`$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

              pre_hash="absent"
              if [[ -f /opt/cowrie/etc/userdb.txt ]]; then
                pre_hash="`$(sha256sum /opt/cowrie/etc/userdb.txt | cut -d' ' -f1)"
              fi
              echo "AUTH_PARITY_PRE_USERDB_SHA256=`${!pre_hash}"

              pid_before="`$(systemctl show -p MainPID --value cowrie.service 2>/dev/null || echo unknown)"
              echo "AUTH_PARITY_COWRIE_PID_BEFORE=`${!pid_before}"

              listener_before="`$(ss -ltn 'sport = :2222' 2>/dev/null | tail -n +2 || true)"
              echo "AUTH_PARITY_LISTENER_BEFORE=`${!listener_before:-none}"

              active_conn_before="`$(ss -tn state established 'sport = :2222' 2>/dev/null | tail -n +2 | wc -l)"
              echo "AUTH_PARITY_ACTIVE_CONNECTIONS_BEFORE=`${!active_conn_before}"

              install -d -m 0755 -o root -g root /opt/patriotpot-bootstrap
              AWS_CONFIG_FILE=/etc/aws/config aws s3api get-object \
                --bucket '`${EvidenceBucket}' \
                --key 'bootstrap/`${AuthParityBundleId}/userdb.txt' \
                /opt/patriotpot-bootstrap/userdb.txt.new \
                --output json \
                --profile patriotpot \
                --region us-east-1
              printf '%s  %s\n' \
                '`${UserdbTxtSha256}' \
                /opt/patriotpot-bootstrap/userdb.txt.new |
                sha256sum --check --status
              sed -i 's/\r`$//' /opt/patriotpot-bootstrap/userdb.txt.new
              install -m 0644 -o root -g root \
                /opt/patriotpot-bootstrap/userdb.txt.new \
                /opt/cowrie/etc/userdb.txt
              rm -f /opt/patriotpot-bootstrap/userdb.txt.new

              echo "AUTH_PARITY_T_INSTALL=`$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
              echo "AUTH_PARITY_POST_USERDB_SHA256=`$(sha256sum /opt/cowrie/etc/userdb.txt | cut -d' ' -f1)"

              echo "AUTH_PARITY_T_RESTART_INITIATED=`$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
              systemctl try-restart cowrie.service
              systemctl is-active --quiet cowrie.service
              echo "AUTH_PARITY_T_RESTART_ACTIVE=`$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

              pid_after="`$(systemctl show -p MainPID --value cowrie.service 2>/dev/null || echo unknown)"
              echo "AUTH_PARITY_COWRIE_PID_AFTER=`${!pid_after}"

              listener_after="`$(ss -ltn 'sport = :2222' 2>/dev/null | tail -n +2 || true)"
              echo "AUTH_PARITY_LISTENER_AFTER=`${!listener_after:-none}"

              active_conn_after="`$(ss -tn state established 'sport = :2222' 2>/dev/null | tail -n +2 | wc -l)"
              echo "AUTH_PARITY_ACTIVE_CONNECTIONS_AFTER=`${!active_conn_after}"

"@
    $text = Set-AnchoredInsertion $text $assocAnchor ($assocAnchor + $assocInsert) "PatriotPotAuthParityAssociation resource"

    return $text
}

function Set-AnchoredInsertion([string]$Text, [string]$Anchor, [string]$Replacement, [string]$Description) {
    $first = $Text.IndexOf($Anchor)
    $last = $Text.LastIndexOf($Anchor)
    if ($first -lt 0) {
        throw "Auth-parity template patch failed: anchor for '$Description' was not found in the base template. Fail closed rather than guess an insertion point."
    }
    if ($first -ne $last) {
        throw "Auth-parity template patch failed: anchor for '$Description' occurs more than once in the base template; insertion point is ambiguous. Fail closed."
    }
    return $Text.Substring(0, $first) + $Replacement + $Text.Substring($first + $Anchor.Length)
}

function New-AuthParityTemplateSnapshot {
    param(
        [string]$BaseTemplateText,
        [string]$BaseProvenance
    )
    # Testability/offline-review seam: callers may supply $BaseTemplateText
    # directly (e.g. a git-verified stand-in when live AWS access is not
    # available). Production use omits it and fetches the real deployed
    # template.
    if (-not $BaseTemplateText) {
        $BaseTemplateText = Get-DeployedTemplateText
        $BaseProvenance = "aws cloudformation get-template --stack-name $StackName (live deployed template)"
    }
    $patched = Add-AuthParityTemplatePatch $BaseTemplateText
    $snapshotDir = Join-Path ([System.IO.Path]::GetTempPath()) "patriotpot-auth-parity-snapshot"
    New-Item -ItemType Directory -Force -Path $snapshotDir | Out-Null
    $snapshotPath = Join-Path $snapshotDir "gmu-honeypot-stack-2026-control.auth-parity-snapshot.yaml"
    [System.IO.File]::WriteAllText($snapshotPath, $patched, [System.Text.UTF8Encoding]::new($false))
    $hash = Get-Sha256 $snapshotPath
    return [pscustomobject]@{
        Path           = $snapshotPath
        Sha256         = $hash
        BaseProvenance = $BaseProvenance
    }
}

function ConvertTo-CanonicalJson($Value) {
    # Deterministic re-serialization for structural equality comparison:
    # object keys sorted alphabetically (so key ordering differences never
    # register as a difference), array element order preserved exactly
    # (order IS significant for everything except the one Resource-list
    # mutation this gate permits, which is handled by removing that one
    # element before this function is ever called -- see
    # Remove-SingleArnOccurrence). This is comparison-only plumbing, never
    # written back to CloudFormation.
    if ($null -eq $Value) {
        return "null"
    }
    if ($Value -is [string]) {
        return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
    }
    if ($Value -is [bool]) {
        return $(if ($Value) { "true" } else { "false" })
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $names = @($Value.PSObject.Properties.Name | Sort-Object)
        $parts = foreach ($name in $names) {
            (ConvertTo-CanonicalJson $name) + ":" + (ConvertTo-CanonicalJson $Value.$name)
        }
        return "{" + ($parts -join ",") + "}"
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($item in $Value) { ConvertTo-CanonicalJson $item }
        return "[" + ($parts -join ",") + "]"
    }
    return "$Value"
}

function ConvertFrom-PoliciesText([string]$Text) {
    # Empirically confirmed shape (real describe-change-set call, auth-parity
    # gate, 2026-09-19): a Details[] entry for a changed inline policy on
    # AWS::IAM::Role carries BeforeValue/AfterValue *nested under Target*,
    # not as top-level Detail properties -- and each value is a single
    # PolicyDocument object ({"Version":...,"Statement":[...]}), not a
    # "Policies" array/wrapper. CFN only emits a Details[] entry for a
    # policy that actually changed, so this document IS the one that
    # changed; no PolicyName is present or needed to identify it. Returns
    # $null (never a guess) on anything that doesn't parse as a
    # {Statement:[...]} document, so the caller can fail closed.
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
    try {
        $parsed = $Text | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
    if ($null -eq $parsed -or -not ($parsed.PSObject.Properties.Name -contains "Statement")) {
        return $null
    }
    return $parsed
}

function Remove-SingleArnOccurrence([object]$PolicyDocument, [string]$ExpectedArn) {
    # Returns a deep-cloned copy of $PolicyDocument (a single {Version,
    # Statement} object) with exactly one occurrence of $ExpectedArn
    # removed from any statement's Resource list. Throws (never silently
    # proceeds) unless exactly one occurrence was found and removed, so the
    # caller's before/after comparison is meaningful.
    $cloneJson = (ConvertTo-Json -InputObject $PolicyDocument -Depth 30)
    $clone = ConvertFrom-Json -InputObject $cloneJson

    # Count every occurrence across every statement FIRST -- including
    # duplicates within a single Resource list -- so "exactly one" is a real
    # guarantee, not "one per statement".
    $totalOccurrences = 0
    foreach ($stmt in @($clone.Statement)) {
        if (-not ($stmt.PSObject.Properties.Name -contains "Resource")) { continue }
        if ($stmt.Resource -is [string]) {
            if ($stmt.Resource -eq $ExpectedArn) { $totalOccurrences++ }
            continue
        }
        foreach ($entry in @($stmt.Resource)) {
            if ($entry -eq $ExpectedArn) { $totalOccurrences++ }
        }
    }
    if ($totalOccurrences -ne 1) {
        throw "Expected exactly one occurrence of the approved ARN in the changed policy document to remove for reduction; found $totalOccurrences."
    }

    foreach ($stmt in @($clone.Statement)) {
        if (-not ($stmt.PSObject.Properties.Name -contains "Resource")) { continue }
        if ($stmt.Resource -is [string]) { continue }
        $list = @($stmt.Resource)
        $idx = -1
        for ($i = 0; $i -lt $list.Count; $i++) {
            if ($list[$i] -eq $ExpectedArn) { $idx = $i; break }
        }
        if ($idx -ge 0) {
            $reduced = @()
            for ($i = 0; $i -lt $list.Count; $i++) {
                if ($i -ne $idx) { $reduced += $list[$i] }
            }
            $stmt.Resource = $reduced
            break
        }
    }
    return $clone
}

function Assert-InstanceRoleChangeIsAuthParityOnly([object]$RoleResourceChange, [string]$ExpectedArn) {
    # Full structural Before/After comparison, per instruction: this is not
    # a set-of-ARNs diff. The AFTER policy document is reduced by removing
    # exactly the one approved ARN addition, then compared for EXACT
    # canonical equality against the BEFORE policy document. Any other
    # difference anywhere -- an extra ARN in this or any other statement,
    # an Action/Effect/Condition change, a statement addition/removal --
    # means the reduced-after no longer equals before, and this throws.
    # If a SECOND inline policy on the role also changed (e.g. H2's
    # Discord-intel ARN landing in a different policy), CFN emits a SECOND
    # Details[] entry for it -- more than one candidate here is itself a
    # scope violation, not an ambiguity to resolve; fails closed either way.
    $details = @($RoleResourceChange.Details)
    $valuedDetails = @(
        $details | Where-Object {
            $null -ne $_.Target -and
            $_.Target.PSObject.Properties.Name -contains "BeforeValue" -and
            $_.Target.PSObject.Properties.Name -contains "AfterValue" -and
            $null -ne $_.Target.BeforeValue -and $null -ne $_.Target.AfterValue
        }
    )
    if ($valuedDetails.Count -eq 0) {
        throw "Cannot verify PatriotPotInstanceRole scope: no property-level Before/After values were returned for this change. Fail closed."
    }

    $candidates = @(
        $valuedDetails | ForEach-Object {
            $before = ConvertFrom-PoliciesText $_.Target.BeforeValue
            $after = ConvertFrom-PoliciesText $_.Target.AfterValue
            if ($null -ne $before -and $null -ne $after) {
                [pscustomobject]@{ Before = $before; After = $after }
            }
        }
    )
    if ($candidates.Count -eq 0) {
        throw "Cannot verify PatriotPotInstanceRole scope: no Details[] entry's Before/After value could be parsed as a policy document. Fail closed rather than trust an unparseable diff."
    }
    if ($candidates.Count -gt 1) {
        throw "PatriotPotInstanceRole shows $($candidates.Count) separately-changed inline policy documents; the frozen auth-parity scope allows exactly 1 (e.g. an unrelated IAM mutation, such as H2's Discord-intel ARN, coexisting with the correct auth-parity change). Fail closed."
    }

    $before = $candidates[0].Before
    $after = $candidates[0].After
    $reducedAfter = Remove-SingleArnOccurrence $after $ExpectedArn

    $beforeCanon = ConvertTo-CanonicalJson $before
    $reducedAfterCanon = ConvertTo-CanonicalJson $reducedAfter
    if ($beforeCanon -ne $reducedAfterCanon) {
        throw "PatriotPotInstanceRole change contains structural difference(s) beyond the single approved auth-parity ARN addition. Fail closed -- this could be an unrelated IAM mutation (e.g. H2's Discord-intel ARN) coexisting with the correct auth-parity change."
    }
}

function Get-ResourceSubtreeText([string]$TemplateText, [string]$LogicalResourceId) {
    # Text-level extraction, same style as Get-TemplateParameterNames: find
    # the top-level "  <Id>:" key and take everything up to (not including)
    # the next top-level "  <Letter...>" key.
    $normalized = $TemplateText -replace "`r`n", "`n"
    $startPattern = "(?m)^  $([regex]::Escape($LogicalResourceId)):\s*$"
    $m = [regex]::Match($normalized, $startPattern)
    if (-not $m.Success) {
        throw "Could not locate resource '$LogicalResourceId' in the supplied template text."
    }
    $rest = $normalized.Substring($m.Index)
    $afterHeader = $rest.Substring($LogicalResourceId.Length + 5)
    $nextMatch = [regex]::Match($afterHeader, "(?m)^  [A-Za-z]")
    if ($nextMatch.Success) {
        return $rest.Substring(0, $LogicalResourceId.Length + 5 + $nextMatch.Index)
    }
    return $rest
}

function Assert-EvidenceBucketPolicyChangeIsDependencyOnly(
    [object]$ResourceChange,
    [string]$DeployedSubtreeText,
    [string]$CandidateSubtreeText,
    [string]$ResolvedPrincipalArn,
    [string]$LiveBucketPolicyJson,
    [string]$ResolvedCandidatePolicyJson
) {
    # Narrow, proof-gated exception -- not a blanket allowance. Every input
    # here must be independently supplied by the caller (read-only
    # iam:GetRole / s3:GetBucketPolicy / template text, never fetched by
    # this function itself, so it stays a pure, unit-testable check). Any
    # missing or mismatched input fails closed.
    if ($ResourceChange.LogicalResourceId -ne "EvidenceBucketPolicy") {
        throw "Assert-EvidenceBucketPolicyChangeIsDependencyOnly called for the wrong resource: $($ResourceChange.LogicalResourceId)"
    }
    if ($ResourceChange.Action -ne "Modify") {
        throw "EvidenceBucketPolicy is not a Modify; found: $($ResourceChange.Action). Fail closed."
    }
    if ($ResourceChange.PSObject.Properties.Name -contains "Replacement" -and $ResourceChange.Replacement -ne "False") {
        throw "EvidenceBucketPolicy Replacement must be False; found: $($ResourceChange.Replacement). Fail closed."
    }

    if ([string]::IsNullOrWhiteSpace($DeployedSubtreeText) -or [string]::IsNullOrWhiteSpace($CandidateSubtreeText)) {
        throw "EvidenceBucketPolicy template subtree text was not supplied. Fail closed."
    }
    $deployedNormalized = ($DeployedSubtreeText -replace "`r`n", "`n").Trim()
    $candidateNormalized = ($CandidateSubtreeText -replace "`r`n", "`n").Trim()
    if ($deployedNormalized -ne $candidateNormalized) {
        throw "EvidenceBucketPolicy template subtree differs between deployed and candidate -- this is not a dependency-reevaluation-only change. Fail closed."
    }

    if ($candidateNormalized -notmatch [regex]::Escape("!GetAtt PatriotPotInstanceRole.Arn")) {
        throw "EvidenceBucketPolicy candidate subtree does not reference !GetAtt PatriotPotInstanceRole.Arn as expected; cannot verify the dependency mechanism. Fail closed."
    }
    if ([string]::IsNullOrWhiteSpace($ResolvedPrincipalArn)) {
        throw "No resolved principal ARN was supplied. Fail closed."
    }

    if ([string]::IsNullOrWhiteSpace($LiveBucketPolicyJson) -or [string]::IsNullOrWhiteSpace($ResolvedCandidatePolicyJson)) {
        throw "Live or resolved-candidate bucket policy was not supplied. Fail closed."
    }
    try {
        $liveObj = $LiveBucketPolicyJson | ConvertFrom-Json -ErrorAction Stop
        $resolvedObj = $ResolvedCandidatePolicyJson | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Bucket policy JSON could not be parsed. Fail closed."
    }
    $liveCanon = ConvertTo-CanonicalJson $liveObj
    $resolvedCanon = ConvertTo-CanonicalJson $resolvedObj
    if ($liveCanon -ne $resolvedCanon) {
        throw "Live bucket policy does not match the resolved candidate bucket policy -- EvidenceBucketPolicy is not proven dependency-reevaluation-only. Fail closed."
    }
}

function Assert-AuthParityChangeSetScope(
    [object]$PlainReview,
    [object]$PropertyReview,
    [string]$ExpectedArn,
    [string]$DeployedTemplateText = $null,
    [string]$CandidateTemplateText = $null,
    [string]$LiveRoleArn = $null,
    [string]$LiveBucketPolicyJson = $null,
    [string]$ResolvedCandidateBucketPolicyJson = $null
) {
    # Mechanically enforces the AUTH-PARITY-GATE freeze; does not define or
    # broaden it. The allowed set below must match evidence/AUTH-PARITY-GATE.md
    # section 8, plus the one narrow, proof-gated EvidenceBucketPolicy
    # dependency-reevaluation exception below -- nothing else.
    $changes = @($PlainReview.Changes)
    $actualResources = @($changes.ResourceChange.LogicalResourceId)

    $deletions = @($changes | Where-Object { $_.ResourceChange.Action -eq "Remove" })
    if ($deletions.Count -gt 0) {
        throw "Auth-parity change set contains a forbidden deletion: $($deletions.ResourceChange.LogicalResourceId -join ', ')"
    }

    $replacements = @(
        $changes | Where-Object {
            $_.ResourceChange.PSObject.Properties.Name -contains "Replacement" -and
            $_.ResourceChange.Replacement -in @("True", "Conditional")
        }
    )
    if ($replacements.Count -gt 0) {
        throw "Auth-parity change set contains a forbidden replacement: $($replacements.ResourceChange.LogicalResourceId -join ', ')"
    }

    $protected = @(
        "PatriotPotInstanceV2", "PatriotPotEIP", "PatriotPotSecurityGroup",
        "VPC", "PublicSubnet", "PublicRouteTable", "PublicRoute",
        "SubnetRouteTableAssociation", "InternetGateway", "AttachGateway",
        "EvidenceBucket",
        "PatriotPotDiscordMonitorAssociation", "PatriotPotEgressFirewallAssociation"
    )
    # EvidenceBucketPolicy is deliberately NOT in this hard-fail list -- it
    # is handled below as a narrowly-scoped, proof-gated exception, never a
    # blanket allowance. Every other resource stays a hard stop.
    $touchedProtected = @($actualResources | Where-Object { $protected -contains $_ })
    if ($touchedProtected.Count -gt 0) {
        throw "Auth-parity change set touches protected resource(s): $($touchedProtected -join ', ')"
    }

    $allowed = @("PatriotPotAuthParityAssociation", "PatriotPotInstanceRole", "EvidenceBucketPolicy")
    $unexpected = @($actualResources | Where-Object { $allowed -notcontains $_ })
    if ($unexpected.Count -gt 0) {
        throw "Auth-parity change set contains resource(s) outside the frozen scope: $($unexpected -join ', ')"
    }

    if ($actualResources -notcontains "PatriotPotAuthParityAssociation") {
        throw "Auth-parity change set is missing the required PatriotPotAuthParityAssociation addition."
    }
    if ($actualResources -notcontains "PatriotPotInstanceRole") {
        throw "Auth-parity change set is missing the required PatriotPotInstanceRole modification."
    }

    $assocChange = ($changes | Where-Object { $_.ResourceChange.LogicalResourceId -eq "PatriotPotAuthParityAssociation" }).ResourceChange
    if ($assocChange.Action -ne "Add") {
        throw "PatriotPotAuthParityAssociation must be an Add; found: $($assocChange.Action)"
    }

    $roleChange = ($changes | Where-Object { $_.ResourceChange.LogicalResourceId -eq "PatriotPotInstanceRole" }).ResourceChange
    if ($roleChange.Action -ne "Modify") {
        throw "PatriotPotInstanceRole must be a Modify; found: $($roleChange.Action)"
    }
    if ($roleChange.PSObject.Properties.Name -contains "Replacement" -and $roleChange.Replacement -ne "False") {
        throw "PatriotPotInstanceRole replacement must be False; found: $($roleChange.Replacement)"
    }

    $propertyEntry = @($PropertyReview.Changes | Where-Object { $_.ResourceChange.LogicalResourceId -eq "PatriotPotInstanceRole" })
    if ($propertyEntry.Count -ne 1) {
        throw "PatriotPotInstanceRole change is missing from the property-value change set; cannot verify scope. Fail closed."
    }
    Assert-InstanceRoleChangeIsAuthParityOnly $propertyEntry[0].ResourceChange $ExpectedArn

    if ($actualResources -contains "EvidenceBucketPolicy") {
        $ebpChange = ($changes | Where-Object { $_.ResourceChange.LogicalResourceId -eq "EvidenceBucketPolicy" }).ResourceChange
        if (-not $DeployedTemplateText -or -not $CandidateTemplateText -or -not $LiveRoleArn -or
            -not $LiveBucketPolicyJson -or -not $ResolvedCandidateBucketPolicyJson) {
            throw "Auth-parity change set touches EvidenceBucketPolicy and no dependency-only proof data was supplied to Assert-AuthParityChangeSetScope. Fail closed -- this is not a blanket allowance."
        }
        $deployedSubtree = Get-ResourceSubtreeText $DeployedTemplateText "EvidenceBucketPolicy"
        $candidateSubtree = Get-ResourceSubtreeText $CandidateTemplateText "EvidenceBucketPolicy"
        Assert-EvidenceBucketPolicyChangeIsDependencyOnly $ebpChange $deployedSubtree $candidateSubtree $LiveRoleArn $LiveBucketPolicyJson $ResolvedCandidateBucketPolicyJson
    }
}

function Assert-TemplateSnapshotParametersAreAccountedFor([string]$TemplateSnapshotPath, [string[]]$DeployedParameterNames) {
    # Step 3-4 of the required flow order: run against the CANDIDATE
    # snapshot, before it is ever used to publish anything or create a
    # change set. Because the snapshot is built from a clean deployed-state
    # base plus exactly the two approved parameters (New-AuthParityTemplateSnapshot),
    # this should always trivially pass -- kept as an explicit, separate
    # check anyway as defense in depth against an unexpectedly-drifted base.
    $templateParamNames = Get-TemplateParameterNames $TemplateSnapshotPath
    $allowedNew = @("AuthParityBundleId", "UserdbTxtSha256")
    $unaccountedNew = @(
        $templateParamNames | Where-Object {
            $DeployedParameterNames -notcontains $_ -and $allowedNew -notcontains $_
        }
    )
    if ($unaccountedNew.Count -gt 0) {
        throw "Auth-parity change set blocked: the candidate template snapshot declares parameter(s) not present on the deployed stack and outside this gate's frozen scope ($($unaccountedNew -join ', ')). This means non-auth-parity content (e.g. H2) is present in the snapshot; it must not be published or used to create a change set."
    }
}

function New-AuthParityChangeSet([object]$Bundle, [object]$TemplateSnapshot, [string]$ExpectedArn) {
    # Scope-contamination checking already happened (Assert-TemplateSnapshotParametersAreAccountedFor,
    # called before Publish-AuthParityBundle in the $AuthParity flow below).
    # This function only creates/reviews/guards the real change set, always
    # against $TemplateSnapshot.Path -- never the working tree's $Template,
    # which may carry undeployed H2 edits.
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $name = "auth-parity-$timestamp"

    $templateParamNames = Get-TemplateParameterNames $TemplateSnapshot.Path
    $allowedNew = @("AuthParityBundleId", "UserdbTxtSha256")
    $parameters = @()
    foreach ($paramName in $templateParamNames) {
        if ($allowedNew -contains $paramName) {
            continue
        }
        $parameters += "ParameterKey=$paramName,UsePreviousValue=true"
    }
    $parameters += "ParameterKey=AuthParityBundleId,ParameterValue=$($Bundle.BundleId)"
    $parameters += "ParameterKey=UserdbTxtSha256,ParameterValue=$($Bundle.UserdbSha256)"

    $response = Invoke-Aws cloudformation create-change-set `
        --stack-name $StackName `
        --change-set-name $name `
        --change-set-type UPDATE `
        --description "Control-parity correction: 2025 authentication semantics (evidence/AUTH-PARITY-GATE.md)" `
        --template-body "file://$($TemplateSnapshot.Path)" `
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
    # change. The plain listing is authoritative for "which resources changed
    # at all"; the property-values listing is used only for the deep IAM
    # diff in Assert-InstanceRoleChangeIsAuthParityOnly.
    $plainReview = Invoke-Aws cloudformation describe-change-set `
        --stack-name $StackName `
        --change-set-name $response.Id `
        --output json | ConvertFrom-Json

    Assert-AuthParityChangeSetScope $plainReview $review $ExpectedArn

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

if ($AuthParity) {
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
    Write-Host "Auth-parity preflight PASS"
    Write-Host "Cowrie host key and Discord credential: not accessed"
    Write-Host "Existing instance: $currentInstanceId (protected from replacement)"
    Write-Host "Template ingress declaration: unchanged (TCP/2222 only)"
    Write-Host "Scope: PatriotPotAuthParityAssociation (Add) + PatriotPotInstanceRole (Modify, one explicit S3 ARN) only"

    if ($PreflightOnly) {
        return
    }

    # Required order past this point (do not reorder): resolve a clean
    # candidate template BEFORE any AWS write, validate it is free of
    # undeployed non-auth-parity scope (H2) BEFORE any AWS write, and only
    # then publish the bundle. Running this against today's H2-mixed
    # working tree must throw here, before Publish-AuthParityBundle, not
    # after.
    Section "RESOLVE AUTH-PARITY-ONLY TEMPLATE SNAPSHOT"
    $snapshot = New-AuthParityTemplateSnapshot
    Write-Host "Snapshot base: $($snapshot.BaseProvenance)"
    Write-Host "Snapshot path: $($snapshot.Path)"
    Write-Host "Snapshot SHA-256: $($snapshot.Sha256)"

    $deployedParamNames = @($stack.Stacks[0].Parameters.ParameterKey)
    Assert-TemplateSnapshotParametersAreAccountedFor $snapshot.Path $deployedParamNames
    Write-Host "Snapshot parameter scope verified: no undeployed non-auth-parity parameters present."

    Section "PUBLISH CONTENT-ADDRESSED AUTH-PARITY BUNDLE"
    $bundle = Publish-AuthParityBundle $EvidenceBucket
    Write-Host "Bundle: $($bundle.BundleId)"
    Write-Host "userdb.txt SHA-256: $($bundle.UserdbSha256)"
    if ($bundle.UserdbSha256 -ne "8f4f8645f05f25392adc9cb0963f7a60adaf677d2195dfd588a83c433c6365a6") {
        throw "userdb.txt SHA-256 does not match the frozen auth-parity target hash (8f4f8645f05f25392adc9cb0963f7a60adaf677d2195dfd588a83c433c6365a6). The working file has drifted from the reviewed evidence file; re-review before proceeding."
    }
    $expectedArn = "arn:aws:s3:::$EvidenceBucket/bootstrap/$($bundle.BundleId)/userdb.txt"
    Write-Host "Expected IAM Resource ARN: $expectedArn"

    Section "CREATE AND REVIEW AUTH-PARITY CLOUDFORMATION CHANGE SET"
    $changeSet = New-AuthParityChangeSet $bundle $snapshot $expectedArn
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
            "{0,-35} action={1,-8} replacement={2}" -f
            $change.LogicalResourceId,
            $change.Action,
            $replacement
        )
    }

    if (-not $ExecuteChangeSet) {
        Write-Host "Change set passed the auth-parity allowlist guard (exactly PatriotPotAuthParityAssociation Add + PatriotPotInstanceRole Modify with a single verified explicit S3 ARN, no replacement, no other resource); not executed."
        return
    }

    Section "EXECUTE REVIEWED AUTH-PARITY CHANGE SET"
    Invoke-Aws cloudformation execute-change-set `
        --stack-name $StackName `
        --change-set-name $changeSet.Id
    Invoke-Aws cloudformation wait stack-update-complete --stack-name $StackName
    $final = Invoke-Aws cloudformation describe-stacks `
        --stack-name $StackName `
        --output json | ConvertFrom-Json
    Write-Host "Final stack status: $($final.Stacks[0].StackStatus)"
    Write-Host "Auth-parity correction is now CloudFormation-managed. Capture the AUTH_PARITY_* boundary evidence from the association's SSM command output per evidence/AUTH-PARITY-GATE.md section 10 -- this run's completion is NOT the Epoch A->B boundary; AUTH_PARITY_T_RESTART_ACTIVE is."
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
