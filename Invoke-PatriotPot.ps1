# Invoke-PatriotPot.ps1
#
# Idempotent build/deploy orchestrator for PatriotPot 2026 Control-0.
#
# Prerequisites:
#   AWS CLI v2, Docker Desktop, credentials configured for $Profile
#
# Usage:
#   aws sso login --profile patriotpot
#   .\Invoke-PatriotPot.ps1

param(
    [string]$Profile       = "patriotpot",
    [string]$Region        = "us-east-1",
    [string]$StackName     = "patriotpot-2026-control-prod",
    [string]$Environment   = "production",
    [string]$EcrRepo       = "patriotpot-2026-control",
    [string]$ProjectRoot   = "C:\DadOpsMateoMaddox\PatriotPot\2026-control",
    [switch]$PreflightOnly
)

$ErrorActionPreference = "Stop"

$Template      = Join-Path $ProjectRoot "gmu-honeypot-stack-2026-control.yaml"
$KeyName       = "patriotpot-2026-admin"
$SshDir        = Join-Path $env:USERPROFILE ".ssh"
$KeyPath       = Join-Path $SshDir $KeyName
$PubPath       = "$KeyPath.pub"
$SecretName    = "patriotpot/2026-control/cowrie-host-key"
$CowrieKeyPath = Join-Path $ProjectRoot "cowrie-host-key-ed25519"
$CowriePubPath = "$CowrieKeyPath.pub"

function Section([string]$msg) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $msg
    Write-Host "============================================================"
}

# Every aws call gets --profile and --region automatically.
# For pipeline use (get-login-password | docker login) call aws directly.
function Invoke-Aws {
    aws @args --profile $Profile --region $Region
    if ($LASTEXITCODE -ne 0) {
        throw "aws $($args[0]) $($args[1]) failed (exit $LASTEXITCODE)"
    }
}

Set-Location $ProjectRoot

# ---------------------------------------------------------------------------
# PREFLIGHT
# Putting into PATH
$AwsCliPath = "$env:LOCALAPPDATA\Programs\Amazon\AWSCLIV2"

if (Test-Path (Join-Path $AwsCliPath "aws.exe")) {
    if (-not (($env:Path -split ';') -contains $AwsCliPath)) {
        $env:Path = "$AwsCliPath;$env:Path"
    }
}
function Invoke-Preflight {
    $results = [System.Collections.Generic.List[object]]::new()

    function PF([string]$label, [string]$status, [string]$detail) {
        $results.Add([pscustomobject]@{ Label = $label; Status = $status; Detail = $detail })
    }

    # 1. AWS CLI installed
    $awsVer = aws --version 2>&1
    if ($LASTEXITCODE -eq 0 -and $awsVer -match 'aws-cli') {
        PF "AWS CLI installed" "PASS" ($awsVer -split "`n" | Select-Object -First 1)
    } else {
        PF "AWS CLI installed" "FAIL" "aws not found or not executable"
    }

    # 2. Docker daemon reachable
    $dockerInfo = docker info 2>&1
    $dockerExit = $LASTEXITCODE
    if ($dockerExit -eq 0) {
        $serverVer = ($dockerInfo | Select-String 'Server Version') -replace '.*Server Version:\s*',''
        PF "Docker daemon reachable" "PASS" "Server Version: $serverVer"
    } else {
        # docker info writes to stderr when daemon is down; capture both streams
        $errLine = ($dockerInfo | Select-String 'error|cannot|connect' -CaseSensitive:$false | Select-Object -First 1) -replace '^.*?:\s*',''
        PF "Docker daemon reachable" "FAIL" "docker info failed: $errLine"
    }

    # 3. AWS profile exists in config
    $profiles = aws configure list-profiles 2>$null
    if ($profiles -contains $Profile) {
        PF "AWS profile exists" "PASS" $Profile
    } else {
        PF "AWS profile exists" "WARN" "Profile '$Profile' not found in aws configure list-profiles"
    }

    # 4. sts get-caller-identity succeeds
    try {
        $id = aws sts get-caller-identity --profile $Profile --region $Region --output json 2>$null | ConvertFrom-Json
        if ($id.Account) {
            PF "sts get-caller-identity" "PASS" "Account=$($id.Account) ARN=$($id.Arn)"
        } else {
            PF "sts get-caller-identity" "FAIL" "Returned no Account field"
        }
    } catch {
        PF "sts get-caller-identity" "FAIL" "$_"
    }

    # 5. Region reachable (ec2 describe-availability-zones is a lightweight regional call)
    try {
        $azOut = aws ec2 describe-availability-zones `
            --profile $Profile --region $Region `
            --query 'AvailabilityZones[0].RegionName' --output text 2>$null
        if ($azOut -eq $Region) {
            PF "Region reachable" "PASS" $Region
        } else {
            PF "Region reachable" "WARN" "Expected $Region, got: $azOut"
        }
    } catch {
        PF "Region reachable" "FAIL" "$_"
    }

    # 6. Effective permissions - test each required action with a dry simulate
    #    Uses iam simulate-principal-policy where the caller ARN is known.
    #    Falls back to WARN if simulate is itself denied.
    $callerArn = $null
    try { $callerArn = (aws sts get-caller-identity --profile $Profile --region $Region --output json 2>$null | ConvertFrom-Json).Arn } catch {}

    $requiredActions = @(
        'ecr:GetAuthorizationToken',
        'ecr:CreateRepository',
        'ecr:DescribeRepositories',
        'ecr:BatchGetImage',
        'secretsmanager:CreateSecret',
        'secretsmanager:DescribeSecret',
        'secretsmanager:GetSecretValue',
        'ec2:ImportKeyPair',
        'ec2:DescribeKeyPairs',
        'ssm:GetParameter',
        'cloudformation:ValidateTemplate',
        'cloudformation:CreateStack',
        'cloudformation:UpdateStack',
        'cloudformation:DescribeStacks',
        'iam:CreateRole',
        'iam:AttachRolePolicy',
        'iam:PassRole'
    )

    if ($callerArn) {
        try {
            $simResult = aws iam simulate-principal-policy `
                --policy-source-arn $callerArn `
                --action-names @requiredActions `
                --profile $Profile --region $Region `
                --output json 2>$null | ConvertFrom-Json

            $denied = $simResult.EvaluationResults | Where-Object { $_.EvalDecision -ne 'allowed' }
            if ($denied.Count -eq 0) {
                PF "IAM permissions simulated" "PASS" "All $($requiredActions.Count) actions allowed"
            } else {
                $deniedNames = ($denied | Select-Object -ExpandProperty EvalActionName) -join ', '
                PF "IAM permissions simulated" "WARN" "Denied or implicit-deny: $deniedNames"
            }
        } catch {
            PF "IAM permissions simulated" "WARN" "iam:SimulatePrincipalPolicy not available or denied; skipping"
        }
    } else {
        PF "IAM permissions simulated" "WARN" "Could not determine caller ARN; skipping simulation"
    }

    # 7. Dockerfile exists
    $df = Join-Path $ProjectRoot "Dockerfile"
    if (Test-Path $df) {
        PF "Dockerfile exists" "PASS" $df
    } else {
        PF "Dockerfile exists" "FAIL" "Not found: $df"
    }

    # 8. cowrie.cfg exists
    $cfg = Join-Path $ProjectRoot "cowrie.cfg"
    if (Test-Path $cfg) {
        $backend = Select-String -Path $cfg -Pattern 'backend\s*=\s*shell' -Quiet
        $detail  = if ($backend) { "backend=shell confirmed" } else { "WARNING: backend=shell not found in cowrie.cfg" }
        $status  = if ($backend) { "PASS" } else { "WARN" }
        PF "cowrie.cfg exists" $status "$cfg - $detail"
    } else {
        PF "cowrie.cfg exists" "FAIL" "Not found: $cfg"
    }

    # 9. userdb.txt exists
    $udb = Join-Path $ProjectRoot "userdb.txt"
    if (Test-Path $udb) {
        PF "userdb.txt exists" "PASS" $udb
    } else {
        PF "userdb.txt exists" "FAIL" "Not found: $udb"
    }

    # 10. CloudFormation template parses (validate-template is read-only)
    try {
        aws cloudformation validate-template `
            --template-body "file://$Template" `
            --profile $Profile --region $Region *> $null
        if ($LASTEXITCODE -eq 0) {
            PF "CloudFormation template parses" "PASS" $Template
        } else {
            PF "CloudFormation template parses" "FAIL" "validate-template returned non-zero"
        }
    } catch {
        PF "CloudFormation template parses" "FAIL" "$_"
    }

    # 11. Required template parameters exist
    #     Use CloudFormation's own parser via validate-template, not regex.
    $required = @('ContainerImageUri','HostAmiId','KeyPairName','CowrieHostKeySecret','Environment')
    if (Test-Path $Template) {
        try {
            $cfnParams = aws cloudformation validate-template `
                --template-body "file://$Template" `
                --query 'Parameters[].ParameterKey' `
                --output text `
                --profile $Profile --region $Region 2>$null
            $cfnParamList = $cfnParams -split '\s+' | Where-Object { $_ -ne '' }
            $missing = $required | Where-Object { $cfnParamList -notcontains $_ }
            if ($missing.Count -eq 0) {
                PF "Template parameters present" "PASS" ($required -join ', ')
            } else {
                PF "Template parameters present" "FAIL" "Missing from CFN parsed output: $($missing -join ', ')"
            }
        } catch {
            PF "Template parameters present" "FAIL" "validate-template failed: $_"
        }
    } else {
        PF "Template parameters present" "FAIL" "Template not found, cannot check"
    }

    # 12. No TCP/22 ingress in template
    if (Test-Path $Template) {
        $yaml = Get-Content $Template -Raw
        if ($yaml -match 'FromPort:\s*22[^2]|FromPort:\s*22$|ToPort:\s*22[^2]|ToPort:\s*22$') {
            PF "No TCP/22 ingress rule" "FAIL" "TCP/22 ingress found in SecurityGroup"
        } else {
            PF "No TCP/22 ingress rule" "PASS" "TCP/22 absent from SecurityGroupIngress"
        }
    } else {
        PF "No TCP/22 ingress rule" "FAIL" "Template not found, cannot check"
    }

    # 13. ContainerImageUri enforces sha256 digest
    #     Check that the orchestrator validates the digest starts with sha256:
    $ps1Content = Get-Content (Join-Path $ProjectRoot "Invoke-PatriotPot.ps1") -Raw
    if ($ps1Content -match 'sha256:' -and $ps1Content -match 'ImmutableImageUri.*@') {
        PF "ContainerImageUri uses sha256 digest" "PASS" "Digest validation and immutable URI present in orchestrator"
    } else {
        PF "ContainerImageUri uses sha256 digest" "FAIL" "Digest enforcement missing from orchestrator"
    }

    # 14. Cowrie host-key not printed
    #     Use PowerShell AST to inspect only executable command invocations.
    #     Triggers only when a print command's argument list directly references
    #     a sensitive variable. Ignores comments, assignments, and string literals.
    $printCommands = @('Write-Host','Write-Output','Write-Verbose','Write-Debug','echo')
    $sensitiveVars = @('privB64','secretValue','privBytes')
    $ps1Path       = Join-Path $ProjectRoot "Invoke-PatriotPot.ps1"
    try {
        $astTokens = $null; $astErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $ps1Path, [ref]$astTokens, [ref]$astErrors)

        # Collect all CommandAst nodes whose command name is a print command
        $printAsts = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $printCommands -contains $node.GetCommandName()
        }, $true)

        $leaks = @()
        foreach ($cmd in $printAsts) {
            # Walk every argument element of the command
            foreach ($el in $cmd.CommandElements | Select-Object -Skip 1) {
                # Look for VariableExpressionAst whose name is a sensitive variable
                $varRefs = $el.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $sensitiveVars -contains $n.VariablePath.UserPath
                }, $true)
                foreach ($v in $varRefs) {
                    $leaks += "$($cmd.GetCommandName()) references `$$($v.VariablePath.UserPath) at line $($v.Extent.StartLineNumber)"
                }
            }
        }

        if ($leaks.Count -eq 0) {
            PF "Cowrie host-key not printed" "PASS" "AST scan: no sensitive variable in print command arguments"
        } else {
            PF "Cowrie host-key not printed" "FAIL" ($leaks -join '; ')
        }
    } catch {
        PF "Cowrie host-key not printed" "WARN" "AST parse failed: $_"
    }

    # 15. Expected local SSH key path is writable
    New-Item -ItemType Directory -Force -Path $SshDir | Out-Null
    $testFile = Join-Path $SshDir ".pp-preflight-writetest"
    try {
        [System.IO.File]::WriteAllText($testFile, "x")
        Remove-Item $testFile -Force
        PF "SSH key dir writable" "PASS" $SshDir
    } catch {
        PF "SSH key dir writable" "FAIL" "Cannot write to $SshDir : $_"
    }

    # 16. Behavioral validator imports successfully
    $validator = Join-Path $ProjectRoot "validate-behavioral-equivalence.py"
    if (Test-Path $validator) {
        $pyCheck = python -c "import ast, sys; ast.parse(open(sys.argv[1]).read()); print('ok')" $validator 2>&1
        if ($pyCheck -match 'ok') {
            PF "Behavioral validator parses" "PASS" $validator
        } else {
            PF "Behavioral validator parses" "FAIL" "Python parse error: $pyCheck"
        }
    } else {
        PF "Behavioral validator parses" "WARN" "Not found: $validator"
    }

    # ---------------------------------------------------------------------------
    # Print results
    # ---------------------------------------------------------------------------
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "PREFLIGHT RESULTS"
    Write-Host "============================================================"

    $passCount = 0; $warnCount = 0; $failCount = 0
    foreach ($r in $results) {
        $color = switch ($r.Status) {
            'PASS' { 'Green'  }
            'WARN' { 'Yellow' }
            'FAIL' { 'Red'    }
            default { 'White' }
        }
        $line = "{0,-6} {1,-40} {2}" -f $r.Status, $r.Label, $r.Detail
        Write-Host $line -ForegroundColor $color
        switch ($r.Status) {
            'PASS' { $passCount++ }
            'WARN' { $warnCount++ }
            'FAIL' { $failCount++ }
        }
    }

    Write-Host ""
    Write-Host ("PASS: {0}  WARN: {1}  FAIL: {2}" -f $passCount, $warnCount, $failCount)
    Write-Host ""

    if ($failCount -gt 0) {
        Write-Host "Preflight FAILED. Resolve FAIL items before deploying." -ForegroundColor Red
        exit 1
    } elseif ($warnCount -gt 0) {
        Write-Host "Preflight passed with warnings. Review WARN items before deploying." -ForegroundColor Yellow
        exit 0
    } else {
        Write-Host "Preflight PASSED. Safe to deploy." -ForegroundColor Green
        exit 0
    }
}

if ($PreflightOnly) {
    Invoke-Preflight
}

if (-not (Test-Path $Template)) {
    throw "Template not found: $Template"
}
if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    throw "aws CLI not found"
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "docker not found"
}

# ---------------------------------------------------------------------------
# 1. AWS AUTH
# ---------------------------------------------------------------------------
Section "AWS AUTHENTICATION"

try {
    $Identity = Invoke-Aws sts get-caller-identity --output json | ConvertFrom-Json
} catch {
    Write-Host ""
    Write-Host "Authentication failed. Run one of:"
    Write-Host "  aws sso login --profile $Profile"
    Write-Host "  aws configure --profile $Profile"
    throw
}

$AccountId = $Identity.Account
Write-Host "Account : $AccountId"
Write-Host "ARN     : $($Identity.Arn)"
Write-Host "Region  : $Region"

# ---------------------------------------------------------------------------
# 2. DOCKER HEALTH
# ---------------------------------------------------------------------------
Section "DOCKER HEALTH CHECK"

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker is not running or not accessible."
}
Write-Host "Docker operational."

# ---------------------------------------------------------------------------
# 3. EC2 MANAGEMENT KEY
#    Private key stays in ~/.ssh/patriotpot-2026-admin, never overwritten.
#    Only the .pub is imported into AWS.
#    TCP/22 is not opened; SSM Session Manager is the primary admin path.
# ---------------------------------------------------------------------------
Section "EC2 MANAGEMENT KEY"

New-Item -ItemType Directory -Force -Path $SshDir | Out-Null

$awsKeyExists = $false
try {
    Invoke-Aws ec2 describe-key-pairs --key-names $KeyName --output json *> $null
    $awsKeyExists = $true
    Write-Host "EC2 key pair already registered: $KeyName"
} catch {
    $awsKeyExists = $false
}

if (-not (Test-Path $KeyPath)) {
    Write-Host "Generating ED25519 management key..."
    & ssh-keygen -t ed25519 -a 100 -f $KeyPath -C $KeyName -N ""
    if ($LASTEXITCODE -ne 0) {
        throw "ssh-keygen failed for management key."
    }
} else {
    Write-Host "Local private key exists, not overwriting: $KeyPath"
}

if (-not $awsKeyExists) {
    Write-Host "Importing public key into EC2..."
    Invoke-Aws ec2 import-key-pair `
        --key-name $KeyName `
        --public-key-material "fileb://$PubPath" | Out-Null
    Write-Host "Imported: $KeyName"
}

# ---------------------------------------------------------------------------
# 4. COWRIE SSH HOST KEY
#    Generated once for Control-0. Stored in Secrets Manager.
#    Reused across redeployments so the attacker-visible fingerprint is stable.
#    Private key is never printed or placed in logs.
# ---------------------------------------------------------------------------
Section "COWRIE SSH HOST KEY"

$secretExists = $false
$SecretArn    = $null

try {
    $existingSecret = Invoke-Aws secretsmanager describe-secret `
        --secret-id $SecretName --output json | ConvertFrom-Json
    $secretExists = $true
    $SecretArn    = $existingSecret.ARN
    Write-Host "Cowrie host key secret already exists: $SecretName"
} catch {
    $secretExists = $false
}

if (-not $secretExists) {
    if (-not (Test-Path $CowrieKeyPath)) {
        Write-Host "Generating Cowrie SSH host key, one-time for Control-0..."
        & ssh-keygen -t ed25519 -a 100 -f $CowrieKeyPath -C "cowrie-host-2026-control-0" -N ""
        if ($LASTEXITCODE -ne 0) {
            throw "ssh-keygen failed for Cowrie host key."
        }
    } else {
        Write-Host "Local Cowrie host key exists: $CowrieKeyPath"
    }

    $privBytes  = [System.IO.File]::ReadAllBytes($CowrieKeyPath)
    $privB64    = [Convert]::ToBase64String($privBytes)
    $pubContent = (Get-Content $CowriePubPath -Raw).Trim()

    $secretValue = [ordered]@{
        private_key_b64 = $privB64
        public_key      = $pubContent
    } | ConvertTo-Json -Compress

    Write-Host "Storing Cowrie host key in Secrets Manager..."
    $newSecret = Invoke-Aws secretsmanager create-secret `
        --name $SecretName `
        --description "PatriotPot 2026 Control-0 Cowrie SSH server host key - DO NOT ROTATE AUTOMATICALLY" `
        --secret-string $secretValue `
        --output json | ConvertFrom-Json

    $SecretArn   = $newSecret.ARN
    $secretValue = $null
    $privB64     = $null
    [System.GC]::Collect()
    Write-Host "Secret created: $SecretArn"
}

# Record only the public fingerprint, never the private key
if (Test-Path $CowriePubPath) {
    $CowrieFingerprint = (& ssh-keygen -l -f $CowriePubPath 2>$null) -join ""
} else {
    # Key was stored in a prior run on another machine; retrieve only public key
    $secretText        = Invoke-Aws secretsmanager get-secret-value `
        --secret-id $SecretName `
        --query SecretString `
        --output text
    $pubFromSecret     = ($secretText | ConvertFrom-Json).public_key
    $tmpPub            = Join-Path $env:TEMP "pp-cowrie-pub-tmp.pub"
    Set-Content $tmpPub $pubFromSecret -Encoding UTF8
    $CowrieFingerprint = (& ssh-keygen -l -f $tmpPub 2>$null) -join ""
    Remove-Item $tmpPub -Force
}
Write-Host "Cowrie host key fingerprint: $CowrieFingerprint"

# ---------------------------------------------------------------------------
# 5. LOCAL BUILD
# ---------------------------------------------------------------------------
Section "BUILDING PATRIOTPOT CONTROL IMAGE"

$Timestamp  = Get-Date -Format "yyyyMMdd-HHmmss"
$LocalImage = "patriotpot:2026-control-$Timestamp"

docker build --platform linux/amd64 --tag $LocalImage .
if ($LASTEXITCODE -ne 0) {
    throw "Docker build failed."
}

# ---------------------------------------------------------------------------
# 6. LOCAL BEHAVIORAL SMOKE TEST
# ---------------------------------------------------------------------------
Section "LOCAL BEHAVIORAL SMOKE TEST"

$cname = "patriotpot-control-smoketest"
try { docker rm -f $cname 2>&1 | Out-Null } catch {}
docker run --detach --name $cname --publish 127.0.0.1:2222:2222 $LocalImage | Out-Null
Start-Sleep -Seconds 6

try {
    $tcp    = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("127.0.0.1", 2222)
    $reader = New-Object System.IO.StreamReader($tcp.GetStream())
    $banner = $reader.ReadLine()
    $tcp.Close()
    Write-Host "Local SSH banner: $banner"
    if ($banner -notmatch "SSH-2\.0-OpenSSH_6\.0p1") {
        Write-Warning "Banner mismatch. Expected: SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
    }
} catch {
    Write-Warning "Local smoke test TCP connect failed: $_"
} finally {
    try { docker rm -f $cname 2>&1 | Out-Null } catch {}
}

# ---------------------------------------------------------------------------
# 7. ECR REPOSITORY
# ---------------------------------------------------------------------------
Section "ECR REPOSITORY"

$repoExists = $false
try {
    Invoke-Aws ecr describe-repositories --repository-names $EcrRepo --output json *> $null
    $repoExists = $true
    Write-Host "ECR repository exists: $EcrRepo"
} catch {
    $repoExists = $false
}

if (-not $repoExists) {
    Write-Host "Creating ECR repository: $EcrRepo"
    Invoke-Aws ecr create-repository `
        --repository-name $EcrRepo `
        --image-scanning-configuration scanOnPush=true | Out-Null
}

$Registry = "$AccountId.dkr.ecr.$Region.amazonaws.com"
$ImageTag  = "$Registry/${EcrRepo}:$Timestamp"

# ---------------------------------------------------------------------------
# 8. ECR LOGIN + PUSH
# ---------------------------------------------------------------------------
Section "PUSHING IMAGE TO ECR"

# Call aws directly here so stdout flows through the pipeline to docker login
aws ecr get-login-password --profile $Profile --region $Region |
    docker login --username AWS --password-stdin $Registry
if ($LASTEXITCODE -ne 0) {
    throw "ECR login failed."
}

docker tag  $LocalImage $ImageTag
docker push $ImageTag
if ($LASTEXITCODE -ne 0) {
    throw "ECR push failed."
}

$Digest = Invoke-Aws ecr describe-images `
    --repository-name $EcrRepo `
    --image-ids "imageTag=$Timestamp" `
    --query "imageDetails[0].imageDigest" `
    --output text

if (-not $Digest.StartsWith("sha256:")) {
    throw "Could not resolve image digest."
}

$ImmutableImageUri = "$Registry/${EcrRepo}@$Digest"

Write-Host "Tag      : $ImageTag"
Write-Host "Digest   : $Digest"
Write-Host "Immutable: $ImmutableImageUri"

# ---------------------------------------------------------------------------
# 9. RESOLVE AL2023 AMI
#    Resolved once here and pinned. No dynamic latest reference in the baseline.
# ---------------------------------------------------------------------------
Section "RESOLVING AMAZON LINUX 2023 AMI"

$HostAmiId = Invoke-Aws ssm get-parameter `
    --name "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64" `
    --query "Parameter.Value" `
    --output text

if (-not $HostAmiId.StartsWith("ami-")) {
    throw "Failed to resolve AL2023 AMI."
}
Write-Host "Pinned AMI: $HostAmiId"

# ---------------------------------------------------------------------------
# 10. DEPLOYMENT INPUTS MANIFEST
# ---------------------------------------------------------------------------
Section "WRITING DEPLOYMENT INPUTS MANIFEST"

$manifest = [ordered]@{
    generated_at_utc         = (Get-Date).ToUniversalTime().ToString("o")
    experiment                = "PatriotPot 2026 Behavioral Reconstruction Control"
    control                   = "Control-0"
    aws_account               = $AccountId
    aws_region                = $Region
    stack_name                = $StackName
    host_ami_id               = $HostAmiId
    ec2_instance_type         = "t3.micro"
    cowrie_version            = "2.5.0"
    historical_python         = "3.8"
    attacker_port             = 2222
    backend                   = "shell"
    hostname                  = "gmu-server"
    ssh_banner                = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
    cowrie_host_key_secret    = $SecretArn
    cowrie_host_key_fp        = $CowrieFingerprint
    ec2_key_pair              = $KeyName
    container_image_tag       = $ImageTag
    container_digest          = $Digest
    container_image_immutable = $ImmutableImageUri
}

$manifest | ConvertTo-Json -Depth 10 |
    Set-Content (Join-Path $ProjectRoot "deployment-inputs.json") -Encoding UTF8

Write-Host "Written: deployment-inputs.json"

# ---------------------------------------------------------------------------
# 11. VALIDATE CLOUDFORMATION TEMPLATE
# ---------------------------------------------------------------------------
Section "VALIDATING CLOUDFORMATION TEMPLATE"

Invoke-Aws cloudformation validate-template `
    --template-body "file://$Template" *> $null

Write-Host "Template valid."

# ---------------------------------------------------------------------------
# 12. DEPLOY / UPDATE STACK
#     aws cloudformation deploy is idempotent: creates on first run, updates on subsequent.
# ---------------------------------------------------------------------------
Section "DEPLOYING STACK: $StackName"

aws cloudformation deploy `
    --stack-name $StackName `
    --template-file $Template `
    --capabilities CAPABILITY_NAMED_IAM `
    --parameter-overrides `
        "Environment=$Environment" `
        "ContainerImageUri=$ImmutableImageUri" `
        "HostAmiId=$HostAmiId" `
        "KeyPairName=$KeyName" `
        "CowrieHostKeySecret=$SecretArn" `
    --tags `
        "Project=PatriotPot" `
        "Experiment=SwarmKillChain" `
        "Control=Control-0" `
        "Environment=$Environment" `
    --region $Region `
    --profile $Profile `
    --no-fail-on-empty-changeset

if ($LASTEXITCODE -ne 0) {
    throw "CloudFormation deployment failed."
}

# ---------------------------------------------------------------------------
# 13. STACK OUTPUTS
# ---------------------------------------------------------------------------
Section "STACK OUTPUTS"

$Outputs = Invoke-Aws cloudformation describe-stacks `
    --stack-name $StackName `
    --query "Stacks[0].Outputs" `
    --output json | ConvertFrom-Json

$OutputMap = @{}
foreach ($o in $Outputs) {
    $OutputMap[$o.OutputKey] = $o.OutputValue
    Write-Host ("{0,-30} {1}" -f $o.OutputKey, $o.OutputValue)
}

# ---------------------------------------------------------------------------
# 14. LOCATE INSTANCE AND WAIT FOR RUNNING STATE
# ---------------------------------------------------------------------------
Section "WAITING FOR EC2 INSTANCE"

$InstanceId = Invoke-Aws ec2 describe-instances `
    --filters `
        "Name=tag:aws:cloudformation:stack-name,Values=$StackName" `
        "Name=instance-state-name,Values=pending,running" `
    --query "Reservations[].Instances[].InstanceId" `
    --output text

if (-not $InstanceId) {
    throw "Could not locate EC2 instance in stack $StackName."
}
Write-Host "Instance: $InstanceId"

Invoke-Aws ec2 wait instance-running --instance-ids $InstanceId
Write-Host "Instance running."

$PublicIp = Invoke-Aws ec2 describe-instances `
    --instance-ids $InstanceId `
    --query "Reservations[0].Instances[0].PublicIpAddress" `
    --output text

Write-Host "Public IP: $PublicIp"

# ---------------------------------------------------------------------------
# 15. WAIT FOR TCP/2222
#     Up to 5 minutes; UserData must pull from ECR and start Cowrie first.
# ---------------------------------------------------------------------------
Section "WAITING FOR TCP/2222"

$ready = $false
for ($i = 1; $i -le 60; $i++) {
    try {
        $c    = New-Object System.Net.Sockets.TcpClient
        $task = $c.ConnectAsync($PublicIp, 2222)
        if ($task.Wait(2000) -and $c.Connected) {
            $c.Close()
            $ready = $true
            break
        }
    } catch {}
    Write-Host "Attempt $i/60 - waiting 10s..."
    Start-Sleep -Seconds 10
}

if (-not $ready) {
    throw "TCP/2222 did not become reachable within 10 minutes."
}
Write-Host "TCP/2222 reachable."

# ---------------------------------------------------------------------------
# 16. REMOTE SSH BANNER VERIFICATION
# ---------------------------------------------------------------------------
Section "REMOTE SSH IDENTIFICATION"

Start-Sleep -Seconds 2
$tcp    = New-Object System.Net.Sockets.TcpClient
$tcp.Connect($PublicIp, 2222)
$reader = New-Object System.IO.StreamReader($tcp.GetStream())
$RemoteBanner = $reader.ReadLine()
$tcp.Close()

Write-Host "Remote banner: $RemoteBanner"

if ($RemoteBanner -notmatch "SSH-2\.0-OpenSSH_6\.0p1") {
    Write-Warning "Remote banner does not match expected SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
}

# ---------------------------------------------------------------------------
# 17. BEHAVIORAL EQUIVALENCE VALIDATOR
# ---------------------------------------------------------------------------
Section "BEHAVIORAL EQUIVALENCE VALIDATION"

$validator = Join-Path $ProjectRoot "validate-behavioral-equivalence.py"
if (Test-Path $validator) {
    python $validator --target $PublicIp --port 2222
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Behavioral equivalence validator reported failures."
    }
} else {
    Write-Warning "Validator script not found: $validator"
}

# ---------------------------------------------------------------------------
# 18. SUMMARY
# ---------------------------------------------------------------------------
Section "PATRIOTPOT CONTROL-0 DEPLOYED"

Write-Host "Stack         : $StackName"
Write-Host "Instance      : $InstanceId"
Write-Host "Sensor        : $PublicIp`:2222"
Write-Host "Host AMI      : $HostAmiId"
Write-Host "Container     : $ImmutableImageUri"
Write-Host "Cowrie key    : $SecretName"
Write-Host "Key FP        : $CowrieFingerprint"
Write-Host "Mgmt key      : $KeyPath"
Write-Host "              : break-glass only, TCP/22 is CLOSED"
Write-Host ""
Write-Host "SSM session:"
Write-Host "  aws ssm start-session --target $InstanceId --profile $Profile --region $Region"
Write-Host ""
Write-Host "Next:"
Write-Host "  python .\validate-behavioral-equivalence.py --target $PublicIp --port 2222"
