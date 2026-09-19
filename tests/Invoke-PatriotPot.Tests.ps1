# Unit tests for the auth-parity change-set guard in Invoke-PatriotPot.ps1.
#
# Invoke-PatriotPot.ps1 is not a pure function library: its bottom ~350 lines
# are top-level script logic (Section "PREFLIGHT", live AWS CLI calls via
# Invoke-Aws, etc.) that would execute for real -- hitting AWS, requiring
# credentials -- if the file were simply dot-sourced. To test the guard
# functions without touching AWS or refactoring the reviewed production
# script's structure, this file extracts only the named function
# definitions from the real file's AST and evaluates just those, verbatim,
# from the actual production source text.
#
# Scope: unit-tests the scope guard (Assert-AuthParityChangeSetScope), the
# deep structural IAM diff (Assert-InstanceRoleChangeIsAuthParityOnly and
# its ConvertTo-CanonicalJson / Remove-SingleArnOccurrence / ConvertFrom-PoliciesText
# building blocks), the template-snapshot patch (Add-AuthParityTemplatePatch,
# run against the real pre-H2 git baseline), Get-TemplateParameterNames, and
# a flow-order regression test over the $AuthParity block's own source text.
# New-AuthParityChangeSet's and New-AuthParityTemplateSnapshot's own
# AWS-calling orchestration is not exercised here -- no function in this
# file has ever had automated coverage of its AWS-calling layer; this suite
# does not change that.

$ScriptPath = Join-Path $PSScriptRoot ".." "Invoke-PatriotPot.ps1"

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw "Invoke-PatriotPot.ps1 failed to parse: $($parseErrors[0].Message)"
}

$FunctionsUnderTest = @(
    "Get-TemplateParameterNames",
    "ConvertTo-CanonicalJson",
    "ConvertFrom-PoliciesText",
    "Remove-SingleArnOccurrence",
    "Assert-InstanceRoleChangeIsAuthParityOnly",
    "Get-ResourceSubtreeText",
    "Assert-EvidenceBucketPolicyChangeIsDependencyOnly",
    "Assert-AuthParityChangeSetScope",
    "Assert-TemplateSnapshotParametersAreAccountedFor",
    "Set-AnchoredInsertion",
    "Add-AuthParityTemplatePatch"
)
foreach ($functionName in $FunctionsUnderTest) {
    $functionAst = $ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName },
        $true
    ) | Select-Object -First 1
    if (-not $functionAst) {
        throw "Could not locate function '$functionName' in $ScriptPath for testing."
    }
    Invoke-Expression $functionAst.Extent.Text
}

$Template = Join-Path $PSScriptRoot ".." "gmu-honeypot-stack-2026-control.yaml"

# ---------------------------------------------------------------------------
# Fixture builders: realistic nested IAM policy structures, not flat ARN
# lists -- the guard now does a full structural diff, so fixtures must look
# like the real PatriotPotInstanceRole shape (PolicyName / PolicyDocument /
# Statement / Effect / Action / Resource / optional Condition).
# ---------------------------------------------------------------------------

$Bucket = "patriotpot-evidence-123456789012-us-east-1"
$ExpectedBundleId = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa1"
$ExpectedArn = "arn:aws:s3:::$Bucket/bootstrap/$ExpectedBundleId/userdb.txt"
$ExistingArns = @(
    "arn:aws:s3:::$Bucket/bootstrap/deadbeef1111deadbeef1111deadbeef1111deadbeef1111deadbeef1111de/discord-monitor.py",
    "arn:aws:s3:::$Bucket/bootstrap/deadbeef1111deadbeef1111deadbeef1111deadbeef1111deadbeef1111de/patriotpot-egress-firewall.sh"
)

# Shape note (empirically confirmed against a real describe-change-set
# response on 2026-09-19, not assumed): a Details[] entry for a changed
# inline policy on AWS::IAM::Role carries BeforeValue/AfterValue NESTED
# UNDER Target, and each value is a single PolicyDocument
# ({"Version":...,"Statement":[...]}) -- no PolicyName, no "Policies"
# wrapper. CFN emits one Details[] entry per policy that actually changed,
# so two changed policies means two entries.

function New-BootstrapReadDocument {
    param(
        [string[]]$ExplicitArns,
        [string[]]$ExplicitActions = @("s3:GetObject"),
        [string]$ExplicitEffect = "Allow",
        [switch]$WithCondition
    )
    $explicitStatement = [ordered]@{
        Effect   = $ExplicitEffect
        Action   = @($ExplicitActions)
        Resource = @($ExplicitArns)
    }
    if ($WithCondition) {
        $explicitStatement["Condition"] = [ordered]@{ StringEquals = [ordered]@{ "aws:PrincipalTag/team" = "control" } }
    }
    return [pscustomobject]@{
        Version   = "2012-10-17"
        Statement = @(
            [pscustomobject]@{
                Effect   = "Allow"
                Action   = @("s3:GetObject")
                Resource = "arn:aws:s3:::$Bucket/bootstrap/wild1111wild1111wild1111wild1111wild1111wild1111wild1111wild111/*"
            },
            [pscustomobject]$explicitStatement
        )
    }
}

function New-DiscordCredentialDocument {
    param([string[]]$Arns = @("arn:aws:ssm:us-east-1:123456789012:parameter/patriotpot/2026-control/discord-webhook"))
    return [pscustomobject]@{
        Version   = "2012-10-17"
        Statement = @(
            [pscustomobject]@{
                Effect   = "Allow"
                Action   = @("ssm:GetParameter")
                Resource = @($Arns)
            }
        )
    }
}

function ConvertTo-PolicyDocumentJsonText([object]$Document) {
    return (ConvertTo-Json -InputObject $Document -Depth 30 -Compress)
}

function New-FakeResourceChange {
    param(
        [string]$LogicalResourceId,
        [string]$Action,
        [string]$Replacement = $null,
        [array]$Details = @()
    )
    $props = [ordered]@{
        LogicalResourceId = $LogicalResourceId
        Action             = $Action
    }
    if ($Replacement) {
        $props["Replacement"] = $Replacement
    }
    $props["Details"] = $Details
    return [pscustomobject]@{ ResourceChange = [pscustomobject]$props }
}

function New-FakeDetail([string]$BeforeValue, [string]$AfterValue) {
    # Before/After live under Target, matching the real API response.
    return [pscustomobject]@{
        Target = [pscustomobject]@{
            Attribute   = "Properties"
            Name        = "Policies"
            Path        = "/Properties/Policies/0/PolicyDocument"
            BeforeValue = $BeforeValue
            AfterValue  = $AfterValue
        }
    }
}

function New-RoleChangeFromDocumentPairs([array]$Pairs) {
    # $Pairs: array of hashtables @{ Before = <document>; After = <document> },
    # one per changed inline policy. Returns the WRAPPED
    # { ResourceChange = ... } shape (one element of $review.Changes);
    # callers invoking Assert-InstanceRoleChangeIsAuthParityOnly directly
    # must unwrap with .ResourceChange themselves.
    $details = @(
        $Pairs | ForEach-Object {
            New-FakeDetail (ConvertTo-PolicyDocumentJsonText $_.Before) (ConvertTo-PolicyDocumentJsonText $_.After)
        }
    )
    return (New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceRole" -Action "Modify" -Replacement "False" `
        -Details $details)
}

function New-ValidAuthParityRoleChange {
    $before = New-BootstrapReadDocument -ExplicitArns $ExistingArns
    $after = New-BootstrapReadDocument -ExplicitArns ($ExistingArns + @($ExpectedArn))
    return (New-RoleChangeFromDocumentPairs @(@{ Before = $before; After = $after }))
}

function New-ValidAssociationChange {
    return New-FakeResourceChange -LogicalResourceId "PatriotPotAuthParityAssociation" -Action "Add"
}

function New-Review([array]$Changes) {
    return [pscustomobject]@{ Changes = $Changes }
}

# ---------------------------------------------------------------------------

Describe "Assert-AuthParityChangeSetScope" {

    It "succeeds for the exact expected Add + Modify combination" {
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange))
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange))
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Not Throw
    }

    It "fails when an unexpected third resource is present" {
        $extra = New-FakeResourceChange -LogicalResourceId "SomeUnrelatedThing" -Action "Modify"
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $extra)
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $extra)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "outside the frozen scope"
    }

    It "fails when any resource shows Replacement=True" {
        $replaced = New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceRole" -Action "Modify" -Replacement "True"
        $plain = New-Review @((New-ValidAssociationChange), $replaced)
        $property = New-Review @((New-ValidAssociationChange), $replaced)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "forbidden replacement"
    }

    It "fails when a resource is deleted" {
        $deleted = New-FakeResourceChange -LogicalResourceId "SomethingElse" -Action "Remove"
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $deleted)
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $deleted)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "forbidden deletion"
    }

    It "fails when the EC2 instance is modified" {
        $instance = New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceV2" -Action "Modify"
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $instance)
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $instance)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "protected resource"
    }

    It "fails when an existing SSM association is modified" {
        $assoc = New-FakeResourceChange -LogicalResourceId "PatriotPotDiscordMonitorAssociation" -Action "Modify"
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $assoc)
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $assoc)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "protected resource"
    }

    It "fails when the security group is touched" {
        $sg = New-FakeResourceChange -LogicalResourceId "PatriotPotSecurityGroup" -Action "Modify"
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $sg)
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $sg)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "protected resource"
    }

    It "fails when a VPC/network resource is touched" {
        $vpc = New-FakeResourceChange -LogicalResourceId "VPC" -Action "Modify"
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $vpc)
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $vpc)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "protected resource"
    }

    It "fails when PatriotPotAuthParityAssociation is missing" {
        $plain = New-Review @((New-ValidAuthParityRoleChange))
        $property = New-Review @((New-ValidAuthParityRoleChange))
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "missing the required PatriotPotAuthParityAssociation"
    }

    It "fails when the PatriotPotInstanceRole modification is missing" {
        $plain = New-Review @((New-ValidAssociationChange))
        $property = New-Review @((New-ValidAssociationChange))
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "missing the required PatriotPotInstanceRole"
    }

    # --- Regression tests required this round: full structural IAM diff ---

    It "fails when a second inline policy also changed (e.g. H2's Discord-intel ARN still mixed in)" {
        # Two changed policies means CFN emits two Details[] entries -- the
        # frozen scope allows exactly one.
        $bootstrapBefore = New-BootstrapReadDocument -ExplicitArns $ExistingArns
        $bootstrapAfter = New-BootstrapReadDocument -ExplicitArns ($ExistingArns + @($ExpectedArn))
        $discordBefore = New-DiscordCredentialDocument
        $discordAfter = New-DiscordCredentialDocument -Arns @(
            "arn:aws:ssm:us-east-1:123456789012:parameter/patriotpot/2026-control/discord-webhook",
            "arn:aws:ssm:us-east-1:123456789012:parameter/patriotpot/2026-control/discord-intel-webhook"
        )
        $roleChange = New-RoleChangeFromDocumentPairs @(
            @{ Before = $bootstrapBefore; After = $bootstrapAfter },
            @{ Before = $discordBefore; After = $discordAfter }
        )
        $plain = New-Review @((New-ValidAssociationChange), $roleChange)
        $property = New-Review @((New-ValidAssociationChange), $roleChange)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "allows exactly 1"
    }

    It "fails when the correct ARN is added alongside an extra ARN in the SAME policy" {
        $extraArn = "arn:aws:s3:::$Bucket/bootstrap/cafebabe2222cafebabe2222cafebabe2222cafebabe2222cafebabe2222ca/discord-monitor.py"
        $before = New-BootstrapReadDocument -ExplicitArns $ExistingArns
        $after = New-BootstrapReadDocument -ExplicitArns ($ExistingArns + @($ExpectedArn, $extraArn))
        $roleChange = New-RoleChangeFromDocumentPairs @(@{ Before = $before; After = $after })
        $plain = New-Review @((New-ValidAssociationChange), $roleChange)
        $property = New-Review @((New-ValidAssociationChange), $roleChange)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "structural difference"
    }

    It "fails when the correct ARN is added alongside an IAM Action expansion" {
        $before = New-BootstrapReadDocument -ExplicitArns $ExistingArns
        $after = New-BootstrapReadDocument -ExplicitArns ($ExistingArns + @($ExpectedArn)) -ExplicitActions @("s3:GetObject", "s3:PutObject")
        $roleChange = New-RoleChangeFromDocumentPairs @(@{ Before = $before; After = $after })
        $plain = New-Review @((New-ValidAssociationChange), $roleChange)
        $property = New-Review @((New-ValidAssociationChange), $roleChange)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "structural difference"
    }

    It "fails when the correct ARN is added alongside an Effect/Condition mutation" {
        $before = New-BootstrapReadDocument -ExplicitArns $ExistingArns
        $after = New-BootstrapReadDocument -ExplicitArns ($ExistingArns + @($ExpectedArn)) -WithCondition
        $roleChange = New-RoleChangeFromDocumentPairs @(@{ Before = $before; After = $after })
        $plain = New-Review @((New-ValidAssociationChange), $roleChange)
        $property = New-Review @((New-ValidAssociationChange), $roleChange)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "structural difference"
    }

    It "fails when the added ARN has the right suffix but the wrong S3 bucket" {
        $wrongBucketArn = "arn:aws:s3:::attacker-controlled-bucket/bootstrap/$ExpectedBundleId/userdb.txt"
        $before = New-BootstrapReadDocument -ExplicitArns $ExistingArns
        $after = New-BootstrapReadDocument -ExplicitArns ($ExistingArns + @($wrongBucketArn))
        $roleChange = New-RoleChangeFromDocumentPairs @(@{ Before = $before; After = $after })
        $plain = New-Review @((New-ValidAssociationChange), $roleChange)
        $property = New-Review @((New-ValidAssociationChange), $roleChange)
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "found 0"
    }
}

Describe "Assert-InstanceRoleChangeIsAuthParityOnly" {

    It "fails closed when no property-level Before/After values are available" {
        $roleChange = (New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceRole" -Action "Modify" -Replacement "False" -Details @()).ResourceChange
        { Assert-InstanceRoleChangeIsAuthParityOnly $roleChange $ExpectedArn } | Should Throw "Fail closed"
    }

    It "fails closed when Before/After values cannot be parsed as a policy document" {
        $roleChange = (New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceRole" -Action "Modify" -Replacement "False" `
            -Details @((New-FakeDetail "not json at all" "also not json"))).ResourceChange
        { Assert-InstanceRoleChangeIsAuthParityOnly $roleChange $ExpectedArn } | Should Throw "Cannot verify"
    }

    It "fails closed when Before/After parse as JSON but are not policy documents" {
        $roleChange = (New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceRole" -Action "Modify" -Replacement "False" `
            -Details @((New-FakeDetail '{"NotAPolicy":true}' '{"NotAPolicy":false}'))).ResourceChange
        { Assert-InstanceRoleChangeIsAuthParityOnly $roleChange $ExpectedArn } | Should Throw "Cannot verify"
    }

    It "fails when an existing ARN is unexpectedly removed alongside the correct one being added" {
        # The reduce-and-compare design (remove exactly the one approved ARN,
        # then require exact structural equality to Before) catches a
        # coincident removal as a general structural difference -- there is
        # no longer a separate "removed" code path, which is intentional:
        # any difference beyond the one approved addition is rejected the
        # same way.
        $before = New-BootstrapReadDocument -ExplicitArns $ExistingArns
        $after = New-BootstrapReadDocument -ExplicitArns @($ExistingArns[0], $ExpectedArn)
        $roleChange = (New-RoleChangeFromDocumentPairs @(@{ Before = $before; After = $after })).ResourceChange
        { Assert-InstanceRoleChangeIsAuthParityOnly $roleChange $ExpectedArn } | Should Throw "structural difference"
    }

    It "succeeds for exactly the one expected added ARN" {
        $before = New-BootstrapReadDocument -ExplicitArns $ExistingArns
        $after = New-BootstrapReadDocument -ExplicitArns ($ExistingArns + @($ExpectedArn))
        $roleChange = (New-RoleChangeFromDocumentPairs @(@{ Before = $before; After = $after })).ResourceChange
        { Assert-InstanceRoleChangeIsAuthParityOnly $roleChange $ExpectedArn } | Should Not Throw
    }
}

# ---------------------------------------------------------------------------
# EvidenceBucketPolicy dependency-reevaluation-only exception fixtures.
# Mirrors the real resource's exact two-statement shape so the template
# subtree comparisons are meaningful, not toy strings.
# ---------------------------------------------------------------------------

$LiveRoleArnFixture = "arn:aws:iam::123456789012:role/patriotpot-instance-role-production"
$OtherRoleArnFixture = "arn:aws:iam::123456789012:role/some-other-role"
$EvidenceBucketArnFixture = "arn:aws:s3:::patriotpot-evidence-123456789012-us-east-1"

function New-EbpSubtreeText {
    param(
        [string]$PrincipalLine = "              AWS: !GetAtt PatriotPotInstanceRole.Arn",
        [string]$ActionLine = "            Action: 's3:PutObject'",
        [string]$ConditionBlock = "            Condition:`n              StringNotEquals:`n                's3:if-none-match': '*'"
    )
    return @"
  EvidenceBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref EvidenceBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: DenyInsecureTransport
            Effect: Deny
            Principal: '*'
            Action: 's3:*'
            Resource:
              - !GetAtt EvidenceBucket.Arn
              - !Sub '`${EvidenceBucket.Arn}/*'
            Condition:
              Bool:
                'aws:SecureTransport': false
          - Sid: DenyUnconditionalControlArchiveWrites
            Effect: Deny
            Principal:
$PrincipalLine
$ActionLine
            Resource: !Sub '`${EvidenceBucket.Arn}/control/`${Environment}/sensors/control-0/instances/*/segments/*'
$ConditionBlock

  EvidenceClaimTable:
"@
}

function New-EbpLiveBucketPolicyJson {
    param([string]$RoleArn = $LiveRoleArnFixture)
    $policy = [ordered]@{
        Version = "2012-10-17"
        Statement = @(
            [ordered]@{
                Sid = "DenyInsecureTransport"
                Effect = "Deny"
                Principal = "*"
                Action = "s3:*"
                Resource = @($EvidenceBucketArnFixture, "$EvidenceBucketArnFixture/*")
                Condition = [ordered]@{ Bool = [ordered]@{ "aws:SecureTransport" = "false" } }
            },
            [ordered]@{
                Sid = "DenyUnconditionalControlArchiveWrites"
                Effect = "Deny"
                Principal = [ordered]@{ AWS = $RoleArn }
                Action = "s3:PutObject"
                Resource = "$EvidenceBucketArnFixture/control/production/sensors/control-0/instances/*/segments/*"
                Condition = [ordered]@{ StringNotEquals = [ordered]@{ "s3:if-none-match" = "*" } }
            }
        )
    }
    return (ConvertTo-Json -InputObject $policy -Depth 10 -Compress)
}

function New-EbpChange {
    param([string]$Action = "Modify", [string]$Replacement = "False", [string]$LogicalResourceId = "EvidenceBucketPolicy")
    return (New-FakeResourceChange -LogicalResourceId $LogicalResourceId -Action $Action -Replacement $Replacement).ResourceChange
}

Describe "Assert-EvidenceBucketPolicyChangeIsDependencyOnly" {

    It "passes for an unchanged dependency-only bucket policy" {
        $deployed = New-EbpSubtreeText
        $candidate = New-EbpSubtreeText
        $live = New-EbpLiveBucketPolicyJson
        $resolved = New-EbpLiveBucketPolicyJson
        {
            Assert-EvidenceBucketPolicyChangeIsDependencyOnly (New-EbpChange) $deployed $candidate $LiveRoleArnFixture $live $resolved
        } | Should Not Throw
    }

    It "fails when the Principal changes between deployed and candidate" {
        $deployed = New-EbpSubtreeText
        $candidate = New-EbpSubtreeText -PrincipalLine "              AWS: !GetAtt SomeOtherRole.Arn"
        $live = New-EbpLiveBucketPolicyJson
        $resolved = New-EbpLiveBucketPolicyJson
        {
            Assert-EvidenceBucketPolicyChangeIsDependencyOnly (New-EbpChange) $deployed $candidate $LiveRoleArnFixture $live $resolved
        } | Should Throw "not a dependency-reevaluation-only"
    }

    It "fails when Action/Resource/Condition changes between deployed and candidate" {
        $deployed = New-EbpSubtreeText
        $candidate = New-EbpSubtreeText -ActionLine "            Action: 's3:*'"
        $live = New-EbpLiveBucketPolicyJson
        $resolved = New-EbpLiveBucketPolicyJson
        {
            Assert-EvidenceBucketPolicyChangeIsDependencyOnly (New-EbpChange) $deployed $candidate $LiveRoleArnFixture $live $resolved
        } | Should Throw "not a dependency-reevaluation-only"
    }

    It "fails when EvidenceBucketPolicy's own Replacement is not False" {
        $deployed = New-EbpSubtreeText
        $candidate = New-EbpSubtreeText
        $live = New-EbpLiveBucketPolicyJson
        $resolved = New-EbpLiveBucketPolicyJson
        {
            Assert-EvidenceBucketPolicyChangeIsDependencyOnly (New-EbpChange -Replacement "True") $deployed $candidate $LiveRoleArnFixture $live $resolved
        } | Should Throw "Fail closed"
    }

    It "fails when role identity effectively changed (resolved candidate policy embeds a different role ARN than the live policy)" {
        # A role identity change (RoleName, Path, etc.) that altered the
        # role's ARN would surface exactly this way: the caller resolves
        # the candidate policy using the (now different) role ARN, and it
        # no longer matches the still-live policy's principal.
        $deployed = New-EbpSubtreeText
        $candidate = New-EbpSubtreeText
        $live = New-EbpLiveBucketPolicyJson -RoleArn $LiveRoleArnFixture
        $resolved = New-EbpLiveBucketPolicyJson -RoleArn $OtherRoleArnFixture
        {
            Assert-EvidenceBucketPolicyChangeIsDependencyOnly (New-EbpChange) $deployed $candidate $LiveRoleArnFixture $live $resolved
        } | Should Throw "does not match the resolved candidate bucket policy"
    }

    It "fails when the live bucket policy does not match the resolved candidate policy for any other reason" {
        $deployed = New-EbpSubtreeText
        $candidate = New-EbpSubtreeText
        $live = New-EbpLiveBucketPolicyJson
        $resolvedObj = $live | ConvertFrom-Json
        $resolvedObj.Statement[0].Condition.Bool.'aws:SecureTransport' = "true"
        $resolved = ConvertTo-Json -InputObject $resolvedObj -Depth 10 -Compress
        {
            Assert-EvidenceBucketPolicyChangeIsDependencyOnly (New-EbpChange) $deployed $candidate $LiveRoleArnFixture $live $resolved
        } | Should Throw "does not match the resolved candidate bucket policy"
    }

    It "fails closed when the bucket policy is unavailable or unparseable" {
        $deployed = New-EbpSubtreeText
        $candidate = New-EbpSubtreeText
        {
            Assert-EvidenceBucketPolicyChangeIsDependencyOnly (New-EbpChange) $deployed $candidate $LiveRoleArnFixture "not valid json" "also not valid json"
        } | Should Throw "Fail closed"
    }

    It "fails closed when no bucket policy text is supplied at all" {
        $deployed = New-EbpSubtreeText
        $candidate = New-EbpSubtreeText
        {
            Assert-EvidenceBucketPolicyChangeIsDependencyOnly (New-EbpChange) $deployed $candidate $LiveRoleArnFixture $null $null
        } | Should Throw "Fail closed"
    }
}

Describe "Assert-AuthParityChangeSetScope (EvidenceBucketPolicy dependency exception, integration-level)" {

    It "PASSES the overall scope check when EvidenceBucketPolicy is present but proven dependency-only" {
        $ebpChange = New-FakeResourceChange -LogicalResourceId "EvidenceBucketPolicy" -Action "Modify" -Replacement "False"
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $ebpChange)
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange))
        $deployedTemplate = New-EbpSubtreeText
        $candidateTemplate = New-EbpSubtreeText
        $live = New-EbpLiveBucketPolicyJson
        $resolved = New-EbpLiveBucketPolicyJson
        {
            Assert-AuthParityChangeSetScope $plain $property $ExpectedArn $deployedTemplate $candidateTemplate $LiveRoleArnFixture $live $resolved
        } | Should Not Throw
    }

    It "still fails closed when EvidenceBucketPolicy is present and no proof data was supplied at all (default behavior unchanged)" {
        $ebpChange = New-FakeResourceChange -LogicalResourceId "EvidenceBucketPolicy" -Action "Modify" -Replacement "False"
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $ebpChange)
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange))
        { Assert-AuthParityChangeSetScope $plain $property $ExpectedArn } | Should Throw "Fail closed"
    }

    It "fails when the role itself shows Replacement=True, even if EvidenceBucketPolicy's own proof would otherwise pass" {
        $roleReplaced = New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceRole" -Action "Modify" -Replacement "True"
        $ebpChange = New-FakeResourceChange -LogicalResourceId "EvidenceBucketPolicy" -Action "Modify" -Replacement "False"
        $plain = New-Review @((New-ValidAssociationChange), $roleReplaced, $ebpChange)
        $property = New-Review @((New-ValidAssociationChange), $roleReplaced)
        $deployedTemplate = New-EbpSubtreeText
        $candidateTemplate = New-EbpSubtreeText
        $live = New-EbpLiveBucketPolicyJson
        $resolved = New-EbpLiveBucketPolicyJson
        {
            Assert-AuthParityChangeSetScope $plain $property $ExpectedArn $deployedTemplate $candidateTemplate $LiveRoleArnFixture $live $resolved
        } | Should Throw "forbidden replacement"
    }

    It "fails when a fourth, unrelated resource is present alongside a provably dependency-only EvidenceBucketPolicy" {
        $ebpChange = New-FakeResourceChange -LogicalResourceId "EvidenceBucketPolicy" -Action "Modify" -Replacement "False"
        $fourth = New-FakeResourceChange -LogicalResourceId "SomeFourthResource" -Action "Modify"
        $plain = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange), $ebpChange, $fourth)
        $property = New-Review @((New-ValidAssociationChange), (New-ValidAuthParityRoleChange))
        $deployedTemplate = New-EbpSubtreeText
        $candidateTemplate = New-EbpSubtreeText
        $live = New-EbpLiveBucketPolicyJson
        $resolved = New-EbpLiveBucketPolicyJson
        {
            Assert-AuthParityChangeSetScope $plain $property $ExpectedArn $deployedTemplate $candidateTemplate $LiveRoleArnFixture $live $resolved
        } | Should Throw "outside the frozen scope"
    }
}

Describe "Get-ResourceSubtreeText" {

    It "extracts exactly the EvidenceBucketPolicy subtree from a larger template fragment" {
        $fragment = "Resources:`n" + (New-EbpSubtreeText) + "`n  AnotherResource:`n    Type: AWS::S3::Bucket`n"
        $subtree = Get-ResourceSubtreeText $fragment "EvidenceBucketPolicy"
        ($subtree -match "DenyUnconditionalControlArchiveWrites") | Should Be $true
        ($subtree -match "AnotherResource") | Should Be $false
    }

    It "throws when the requested resource is not present" {
        $fragment = "Resources:`n  SomethingElse:`n    Type: AWS::S3::Bucket`n"
        { Get-ResourceSubtreeText $fragment "EvidenceBucketPolicy" } | Should Throw "Could not locate"
    }
}

Describe "ConvertTo-CanonicalJson / Remove-SingleArnOccurrence" {

    It "produces identical canonical output regardless of source key order" {
        $a = [pscustomobject]@{ z = 1; a = 2 }
        $b = [pscustomobject]@{ a = 2; z = 1 }
        (ConvertTo-CanonicalJson $a) | Should Be (ConvertTo-CanonicalJson $b)
    }

    It "throws when the expected ARN does not appear exactly once in the policy document" {
        $document = New-BootstrapReadDocument -ExplicitArns $ExistingArns
        { Remove-SingleArnOccurrence $document $ExpectedArn } | Should Throw "found 0"
    }

    It "throws when the expected ARN appears more than once in the policy document" {
        $document = New-BootstrapReadDocument -ExplicitArns ($ExistingArns + @($ExpectedArn, $ExpectedArn))
        { Remove-SingleArnOccurrence $document $ExpectedArn } | Should Throw "found 2"
    }

    It "removes exactly one occurrence and leaves everything else identical" {
        $document = New-BootstrapReadDocument -ExplicitArns ($ExistingArns + @($ExpectedArn))
        $reduced = Remove-SingleArnOccurrence $document $ExpectedArn
        $reducedResource = @($reduced.Statement[1].Resource)
        ($reducedResource -contains $ExpectedArn) | Should Be $false
        $reducedResource.Count | Should Be $ExistingArns.Count
        # everything outside the one removed element is untouched
        (ConvertTo-CanonicalJson $reduced) | Should Be (ConvertTo-CanonicalJson (New-BootstrapReadDocument -ExplicitArns $ExistingArns))
    }
}

Describe "Get-TemplateParameterNames" {

    It "extracts exactly the declared top-level template parameters, including AuthParityBundleId and UserdbTxtSha256" {
        # Pester 3.4's "Should Contain" checks file content, not array
        # membership -- use PowerShell's own -contains operator instead.
        $names = @(Get-TemplateParameterNames $Template)
        ($names -contains "AuthParityBundleId") | Should Be $true
        ($names -contains "UserdbTxtSha256") | Should Be $true
        ($names -contains "HostAmiId") | Should Be $true
        ($names -contains "DiscordWebhookParameterName") | Should Be $true
        # Resource names must never leak in (Resources: starts well after
        # Parameters: in the real template).
        ($names -contains "PatriotPotAuthParityAssociation") | Should Be $false
        ($names -contains "PatriotPotInstanceRole") | Should Be $false
    }
}

Describe "Assert-TemplateSnapshotParametersAreAccountedFor" {

    It "passes when the snapshot's parameters are a subset of deployed params plus the two approved new ones" {
        $deployed = @(Get-TemplateParameterNames $Template) | Where-Object { $_ -notin @("AuthParityBundleId", "UserdbTxtSha256") }
        { Assert-TemplateSnapshotParametersAreAccountedFor $Template $deployed } | Should Not Throw
    }

    It "fails when the candidate template declares a parameter absent from the deployed stack and outside the approved set (e.g. H2 still present)" {
        $deployedMissingWebhookParam = @(Get-TemplateParameterNames $Template) | Where-Object {
            $_ -notin @("AuthParityBundleId", "UserdbTxtSha256", "DiscordWebhookParameterName")
        }
        { Assert-TemplateSnapshotParametersAreAccountedFor $Template $deployedMissingWebhookParam } | Should Throw "outside this gate's frozen scope"
    }
}

Describe "Add-AuthParityTemplatePatch (against the real pre-H2 git baseline)" {
    # 32d89ee is the last commit before the H2 feature commit (3f2c115) and,
    # per this project's established deployment narrative, no CloudFormation
    # execution has happened since -- so it stands in for "the verified
    # deployed baseline" for offline testing. Production use fetches the
    # real live template instead (Get-DeployedTemplateText); this test
    # verifies the patch logic itself, not that assumption.
    $BaselineText = & git -C (Join-Path $PSScriptRoot "..") show 32d89ee:gmu-honeypot-stack-2026-control.yaml 2>$null
    $BaselineText = ($BaselineText -join "`n")

    It "has a non-empty pre-H2 baseline available from git" {
        $BaselineText.Length | Should BeGreaterThan 1000
    }

    It "applies cleanly and inserts each anchor's content exactly once" {
        $patched = Add-AuthParityTemplatePatch $BaselineText
        (@([regex]::Matches($patched, [regex]::Escape("AuthParityBundleId:"))).Count) | Should Be 1
        (@([regex]::Matches($patched, [regex]::Escape("UserdbTxtSha256:"))).Count) | Should Be 1
        (@([regex]::Matches($patched, [regex]::Escape("PatriotPotAuthParityAssociation:"))).Count) | Should Be 1
        (@([regex]::Matches($patched, [regex]::Escape("AUTH_PARITY_T_RESTART_ACTIVE"))).Count) | Should Be 1
    }

    It "produces a patched template containing no H2 markers" {
        $patched = Add-AuthParityTemplatePatch $BaselineText
        ($patched -match "DiscordIntelWebhookParameterName") | Should Be $false
        ($patched -match "PatriotPotThreatIntelCredential") | Should Be $false
    }

    It "throws (fails closed) rather than guessing when an anchor is not found" {
        $mangled = $BaselineText -replace [regex]::Escape("DiscordMonitorSha256:"), "SomethingElseEntirely:"
        { Add-AuthParityTemplatePatch $mangled } | Should Throw "anchor for"
    }

    It "produces output that Get-TemplateParameterNames can read back, with no unaccounted-for parameters versus the baseline" {
        $patched = Add-AuthParityTemplatePatch $BaselineText
        $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "auth-parity-pester-snapshot.yaml"
        [System.IO.File]::WriteAllText($tempPath, $patched, [System.Text.UTF8Encoding]::new($false))
        try {
            $baselineTempPath = Join-Path ([System.IO.Path]::GetTempPath()) "auth-parity-pester-baseline.yaml"
            [System.IO.File]::WriteAllText($baselineTempPath, $BaselineText, [System.Text.UTF8Encoding]::new($false))
            try {
                $baselineParams = @(Get-TemplateParameterNames $baselineTempPath)
                { Assert-TemplateSnapshotParametersAreAccountedFor $tempPath $baselineParams } | Should Not Throw
            } finally {
                Remove-Item -LiteralPath $baselineTempPath -ErrorAction SilentlyContinue
            }
        } finally {
            Remove-Item -LiteralPath $tempPath -ErrorAction SilentlyContinue
        }
    }
}

Describe "AuthParity flow order (regression guard on Invoke-PatriotPot.ps1's own source)" {
    # Not a guard-function unit test -- a structural check on the script's
    # own text that the ordering instruction actually produced: the
    # contamination check must appear, in source order, before the bundle
    # publish call, inside the `if ($AuthParity) { ... }` block. This is
    # what "preflight/template incompatibility occurs before
    # Publish-AuthParityBundle" is regression-tested by.
    $rawSource = Get-Content -LiteralPath $ScriptPath -Raw
    $blockStart = $rawSource.IndexOf("if (`$AuthParity) {")
    $blockEnd = $rawSource.IndexOf("`$ami = Resolve-OfficialAl2Ami")
    $block = $rawSource.Substring($blockStart, $blockEnd - $blockStart)

    It "locates the `$AuthParity flow block" {
        $blockStart | Should BeGreaterThan 0
        $blockEnd | Should BeGreaterThan $blockStart
    }

    It "calls Assert-TemplateSnapshotParametersAreAccountedFor before Publish-AuthParityBundle" {
        # Search for the actual call statements, not bare function names --
        # the block's own explanatory comment mentions "Publish-AuthParityBundle"
        # in prose before the real calls, which would otherwise give this
        # test a false positive location for the bare name.
        $checkIndex = $block.IndexOf("Assert-TemplateSnapshotParametersAreAccountedFor `$snapshot.Path")
        $publishIndex = $block.IndexOf("`$bundle = Publish-AuthParityBundle")
        $checkIndex | Should BeGreaterThan 0
        $publishIndex | Should BeGreaterThan 0
        $checkIndex | Should BeLessThan $publishIndex
    }

    It "resolves the template snapshot before Publish-AuthParityBundle" {
        $snapshotIndex = $block.IndexOf("`$snapshot = New-AuthParityTemplateSnapshot")
        $publishIndex = $block.IndexOf("`$bundle = Publish-AuthParityBundle")
        $snapshotIndex | Should BeGreaterThan 0
        $snapshotIndex | Should BeLessThan $publishIndex
    }

    It "creates the change set from the snapshot, not the working-tree `$Template" {
        # New-AuthParityChangeSet must be invoked with the snapshot variable,
        # not bare $Template, as its second argument in this block.
        ($block -match "New-AuthParityChangeSet\s+\`$bundle\s+\`$snapshot") | Should Be $true
    }
}
