# Unit tests for the H2 change-set guard in Invoke-PatriotPot.ps1.
#
# Same AST-extraction discipline as Invoke-PatriotPot.Tests.ps1 (see that
# file's header for why): this script has top-level logic that hits AWS for
# real if dot-sourced directly, so only the named function definitions are
# extracted from the real production source and evaluated verbatim.
#
# Scope: unit-tests the H2 scope guard (Assert-H2CandidateScope) -- the
# replacement hard-fail, the PatriotPotInstanceV2/UserData exclusion, the
# AuthParity-instrumentation-hitchhiking prohibition and its proof-gated
# -IncludeAuthParityInstrumentationFix exception, the resource allowlist --
# plus the H2 template patch (Add-H2TemplatePatch, run against the real live
# baseline commit), Assert-H2TemplateSnapshotParametersAreAccountedFor, and
# Assert-H2BundleIdNotInInstanceSubtree (v3: the H2BundleId/
# H2DiscordMonitorSha256 artifact-bundle separation from
# FirewallBundleId/BootstrapBundleId -- the actual safety property that
# design exists to guarantee, checked structurally). New-H2ChangeSet's and
# New-H2TemplateSnapshot's own AWS-calling orchestration is not exercised
# here, consistent with the auth-parity suite's stated scope.

$ScriptPath = Join-Path $PSScriptRoot ".." "Invoke-PatriotPot.ps1"

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw "Invoke-PatriotPot.ps1 failed to parse: $($parseErrors[0].Message)"
}

$FunctionsUnderTest = @(
    "Get-TemplateParameterNames",
    "Get-ResourceSubtreeText",
    "Set-AnchoredInsertion",
    "Test-ChangeIsHashSubstitutionOnly",
    "Test-EvidenceBucketPolicyChangeIsDependencyOnly",
    "Assert-H2TemplateSnapshotParametersAreAccountedFor",
    "Assert-H2BundleIdNotInInstanceSubtree",
    "Assert-H2CandidateScope",
    "Add-H2TemplatePatch"
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

# ---------------------------------------------------------------------------
# Fixture builders: describe-change-set-shaped PlainReview objects, matching
# the empirically confirmed real API shape (2026-09-19 auth-parity gate):
# ResourceChange wrapper, Details[] entries with Target.BeforeValue/AfterValue,
# Evaluation ("Static"/"Dynamic").
# ---------------------------------------------------------------------------

function New-FakeResourceChange {
    param(
        [string]$LogicalResourceId,
        [string]$Action = "Modify",
        [string]$Replacement = "False",
        [array]$Details = @()
    )
    $props = [ordered]@{
        LogicalResourceId = $LogicalResourceId
        Action             = $Action
        Details            = $Details
    }
    if ($Replacement) {
        $props["Replacement"] = $Replacement
    }
    return [pscustomobject]@{ ResourceChange = [pscustomobject]$props }
}

function New-PlainReview([array]$Changes) {
    return [pscustomobject]@{ Changes = $Changes }
}

function New-DependencyOnlyDetail {
    return [pscustomobject]@{ Evaluation = "Dynamic" }
}

function New-DirectModificationDetail {
    return [pscustomobject]@{ Evaluation = "Static" }
}

# A minimal, valid H2 change set: exactly the two required resources.
function New-ValidH2Changes {
    return @(
        New-FakeResourceChange -LogicalResourceId "PatriotPotDiscordMonitorAssociation" -Action "Modify" -Replacement "False"
        New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceRole" -Action "Modify" -Replacement "False"
    )
}

# ---------------------------------------------------------------------------
# Assert-H2CandidateScope
# ---------------------------------------------------------------------------

Describe "Assert-H2CandidateScope" {

    It "passes a minimal valid H2 change set (DiscordMonitorAssociation + InstanceRole only)" {
        $review = New-PlainReview (New-ValidH2Changes)
        { Assert-H2CandidateScope -PlainReview $review } | Should Not Throw
    }

    It "fails closed on any Replacement=True, on ANY resource" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "SomeOtherResource" -Action "Modify" -Replacement "True"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review } | Should Throw "forbidden replacement"
    }

    It "fails closed on Replacement=Conditional" {
        $changes = New-ValidH2Changes
        $changes[0].ResourceChange.Replacement = "Conditional"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review } | Should Throw "forbidden replacement"
    }

    It "fails closed if PatriotPotInstanceV2 appears at all, even Modify/Replacement=False (the UserData/instance-replacement case)" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceV2" -Action "Modify" -Replacement "False"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review } | Should Throw "PatriotPotInstanceV2"
    }

    It "fails closed on an unexpected fourth/fifth resource outside the allowlist" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "SomeUnrelatedResource" -Action "Modify" -Replacement "False"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review } | Should Throw "outside the allowlist"
    }

    It "fails closed if a required resource is missing" {
        $changes = @(New-FakeResourceChange -LogicalResourceId "PatriotPotInstanceRole" -Action "Modify" -Replacement "False")
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review } | Should Throw "lacks required resource"
    }

    It "fails closed on a protected resource (e.g. PatriotPotEIP)" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "PatriotPotEIP" -Action "Modify" -Replacement "False"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review } | Should Throw "protected resource"
    }

    It "permits EvidenceBucketPolicy when every Details[] entry is Evaluation=Dynamic (dependency-reevaluation only)" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "EvidenceBucketPolicy" -Action "Modify" -Replacement "False" -Details @(New-DependencyOnlyDetail)
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review } | Should Not Throw
    }

    It "fails closed on EvidenceBucketPolicy when a Details[] entry is Evaluation=Static (a real content change)" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "EvidenceBucketPolicy" -Action "Modify" -Replacement "False" -Details @(New-DirectModificationDetail)
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review } | Should Throw "EvidenceBucketPolicy"
    }

    # --- AuthParity instrumentation hitchhiking prohibition ---

    It "fails closed if PatriotPotAuthParityAssociation appears and -IncludeAuthParityInstrumentationFix was NOT passed (hitchhiking prohibition)" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "PatriotPotAuthParityAssociation" -Action "Modify" -Replacement "False"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review } | Should Throw "hitchhiking"
    }

    It "fails closed if -IncludeAuthParityInstrumentationFix is passed but no proof data is supplied (does not widen the allowlist by itself)" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "PatriotPotAuthParityAssociation" -Action "Modify" -Replacement "False"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review -IncludeAuthParityInstrumentationFix } | Should Throw "requires its own proof data"
    }

    It "fails closed if -IncludeAuthParityInstrumentationFix proof data doesn't match (candidate != expected fixed subtree)" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "PatriotPotAuthParityAssociation" -Action "Modify" -Replacement "False"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review -IncludeAuthParityInstrumentationFix `
            -DeployedAuthParityAssociationSubtreeText "old buggy text" `
            -CandidateAuthParityAssociationSubtreeText "some other text" `
            -ExpectedInstrumentationFixAssociationSubtreeText "the actual fixed text"
        } | Should Throw "does not match the expected"
    }

    It "fails closed if -IncludeAuthParityInstrumentationFix proof shows candidate unchanged from deployed" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "PatriotPotAuthParityAssociation" -Action "Modify" -Replacement "False"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review -IncludeAuthParityInstrumentationFix `
            -DeployedAuthParityAssociationSubtreeText "same text" `
            -CandidateAuthParityAssociationSubtreeText "same text" `
            -ExpectedInstrumentationFixAssociationSubtreeText "same text"
        } | Should Throw "nothing to apply"
    }

    It "permits PatriotPotAuthParityAssociation ONLY when -IncludeAuthParityInstrumentationFix is passed with matching, changed proof data" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "PatriotPotAuthParityAssociation" -Action "Modify" -Replacement "False"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review -IncludeAuthParityInstrumentationFix `
            -DeployedAuthParityAssociationSubtreeText "old buggy text" `
            -CandidateAuthParityAssociationSubtreeText "new fixed text" `
            -ExpectedInstrumentationFixAssociationSubtreeText "new fixed text"
        } | Should Not Throw
    }

    It "still rejects an unrelated resource even when -IncludeAuthParityInstrumentationFix's own proof is valid (the switch is scoped to that one resource, not a general relaxation)" {
        $changes = New-ValidH2Changes
        $changes += New-FakeResourceChange -LogicalResourceId "PatriotPotAuthParityAssociation" -Action "Modify" -Replacement "False"
        $changes += New-FakeResourceChange -LogicalResourceId "SomeUnrelatedResource" -Action "Modify" -Replacement "False"
        $review = New-PlainReview $changes
        { Assert-H2CandidateScope -PlainReview $review -IncludeAuthParityInstrumentationFix `
            -DeployedAuthParityAssociationSubtreeText "old buggy text" `
            -CandidateAuthParityAssociationSubtreeText "new fixed text" `
            -ExpectedInstrumentationFixAssociationSubtreeText "new fixed text"
        } | Should Throw "outside the allowlist"
    }
}

# ---------------------------------------------------------------------------
# Add-H2TemplatePatch (against the real live baseline commit)
# ---------------------------------------------------------------------------

Describe "Add-H2TemplatePatch (against the real retrieved live-deployed template)" {
    # NOT a git commit reference -- see tests/fixtures/README.md. H2's
    # feature commit (3f2c115) precedes every AuthParity commit in this
    # repo's history, so every commit that carries AuthParity content
    # already carries H2 content too; there is no commit reflecting the
    # actual live state ("AuthParity deployed, H2 absent"). This fixture is
    # the verbatim retrieved live template bytes instead
    # (SHA-256 f583e85c..., confirmed HAS_H2_THREATINTEL=False at
    # retrieval), consistent with the project-wide invariant that deployed
    # state comes from CloudFormation, never Git.
    $FixturePath = Join-Path $PSScriptRoot "fixtures" "live-deployed-template-20260919.yaml"
    $BaselineText = [System.IO.File]::ReadAllText($FixturePath) -replace "`r`n", "`n"

    It "has a non-empty live baseline fixture on disk" {
        $BaselineText.Length | Should BeGreaterThan 1000
    }

    It "fixture matches its recorded retrieval-time SHA-256 (has not silently drifted)" {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($BaselineText)
        $hash = [System.BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace("-", "").ToLowerInvariant()
        $hash | Should Be "f583e85c0dde0ed4c108d271c6f34e5c6af97af80459dd05cec2894f8266e28e"
    }

    It "fixture confirms H2 is genuinely absent from the live baseline (precondition for these tests to mean anything)" {
        ($BaselineText -match "PatriotPotThreatIntelCredential") | Should Be $false
        ($BaselineText -match "DiscordIntelWebhookParameterName") | Should Be $false
    }

    It "applies cleanly and inserts each anchor's content exactly once" {
        $patched = Add-H2TemplatePatch $BaselineText
        (@([regex]::Matches($patched, [regex]::Escape("DiscordIntelWebhookParameterName:"))).Count) | Should Be 1
        (@([regex]::Matches($patched, [regex]::Escape("PatriotPotThreatIntelCredential"))).Count) | Should Be 1
        (@([regex]::Matches($patched, [regex]::Escape("fetch_h2_support_file()"))).Count) | Should Be 1
    }

    It "never touches PatriotPotInstanceV2's UserData (H2-U1 is deliberately excluded)" {
        $patched = Add-H2TemplatePatch $BaselineText
        $instanceBefore = Get-ResourceSubtreeText $BaselineText "PatriotPotInstanceV2"
        $instanceAfter = Get-ResourceSubtreeText $patched "PatriotPotInstanceV2"
        $instanceAfter | Should Be $instanceBefore
    }

    It "preserves PatriotPotAuthParityAssociation byte-identically (no hitchhiking)" {
        $patched = Add-H2TemplatePatch $BaselineText
        $before = Get-ResourceSubtreeText $BaselineText "PatriotPotAuthParityAssociation"
        $after = Get-ResourceSubtreeText $patched "PatriotPotAuthParityAssociation"
        $after | Should Be $before
    }

    It "throws (fails closed) rather than guessing when an anchor is not found" {
        $mangled = $BaselineText -replace [regex]::Escape("PatriotPotInstanceProfile:"), "SomethingElseEntirely:"
        { Add-H2TemplatePatch $mangled } | Should Throw "anchor for"
    }

    It "produces output that Assert-H2TemplateSnapshotParametersAreAccountedFor accepts against the baseline's own parameters" {
        $patched = Add-H2TemplatePatch $BaselineText
        $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "h2-pester-snapshot.yaml"
        [System.IO.File]::WriteAllText($tempPath, $patched, [System.Text.UTF8Encoding]::new($false))
        try {
            $baselineTempPath = Join-Path ([System.IO.Path]::GetTempPath()) "h2-pester-baseline.yaml"
            [System.IO.File]::WriteAllText($baselineTempPath, $BaselineText, [System.Text.UTF8Encoding]::new($false))
            try {
                $baselineParams = @(Get-TemplateParameterNames $baselineTempPath)
                { Assert-H2TemplateSnapshotParametersAreAccountedFor $tempPath $baselineParams } | Should Not Throw
            } finally {
                Remove-Item -LiteralPath $baselineTempPath -ErrorAction SilentlyContinue
            }
        } finally {
            Remove-Item -LiteralPath $tempPath -ErrorAction SilentlyContinue
        }
    }

    It "rejects a snapshot carrying an unaccounted-for parameter outside H2's frozen scope" {
        $patched = Add-H2TemplatePatch $BaselineText
        $patched = $patched -replace [regex]::Escape("DiscordIntelWebhookParameterName:"), "SomeUnrelatedNewParameter:"
        $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "h2-pester-contaminated-snapshot.yaml"
        [System.IO.File]::WriteAllText($tempPath, $patched, [System.Text.UTF8Encoding]::new($false))
        try {
            $baselineTempPath = Join-Path ([System.IO.Path]::GetTempPath()) "h2-pester-baseline2.yaml"
            [System.IO.File]::WriteAllText($baselineTempPath, $BaselineText, [System.Text.UTF8Encoding]::new($false))
            try {
                $baselineParams = @(Get-TemplateParameterNames $baselineTempPath)
                { Assert-H2TemplateSnapshotParametersAreAccountedFor $tempPath $baselineParams } | Should Throw "outside H2's frozen scope"
            } finally {
                Remove-Item -LiteralPath $baselineTempPath -ErrorAction SilentlyContinue
            }
        } finally {
            Remove-Item -LiteralPath $tempPath -ErrorAction SilentlyContinue
        }
    }

    It "the real candidate declares H2BundleId and H2DiscordMonitorSha256 as parameters" {
        $patched = Add-H2TemplatePatch $BaselineText
        (@([regex]::Matches($patched, "(?m)^  H2BundleId:\s*`$"))).Count | Should Be 1
        (@([regex]::Matches($patched, "(?m)^  H2DiscordMonitorSha256:\s*`$"))).Count | Should Be 1
    }

    It "PatriotPotDiscordMonitorAssociation references H2BundleId and H2DiscordMonitorSha256" {
        $patched = Add-H2TemplatePatch $BaselineText
        $assocSubtree = Get-ResourceSubtreeText $patched "PatriotPotDiscordMonitorAssociation"
        ($assocSubtree -match [regex]::Escape('${H2BundleId}')) | Should Be $true
        ($assocSubtree -match [regex]::Escape('${H2DiscordMonitorSha256}')) | Should Be $true
    }

    It "PatriotPotInstanceRole grants H2BundleId access for all 15 H2 sidecar files, and leaves the original FirewallBundleId-scoped discord-monitor.py/firewall grants untouched" {
        $patched = Add-H2TemplatePatch $BaselineText
        $roleSubtree = Get-ResourceSubtreeText $patched "PatriotPotInstanceRole"
        foreach ($file in @(
            "discord-monitor.py", "session_cluster.py", "discord_rate_governor.py",
            "threat_intel__init__.py", "threat_intel_worker.py"
        )) {
            ($roleSubtree -match [regex]::Escape("bootstrap/`${H2BundleId}/$file")) | Should Be $true
        }
        # original H1-era grants, unrelated to H2BundleId, must be unchanged
        ($roleSubtree -match [regex]::Escape('bootstrap/${FirewallBundleId}/discord-monitor.py')) | Should Be $true
        ($roleSubtree -match [regex]::Escape('bootstrap/${FirewallBundleId}/patriotpot-egress-firewall.sh')) | Should Be $true
        ($roleSubtree -match [regex]::Escape('bootstrap/${FirewallBundleId}/patriotpot-egress-firewall.service')) | Should Be $true
    }
}

Describe "Assert-H2BundleIdNotInInstanceSubtree" {
    $FixturePath = Join-Path $PSScriptRoot "fixtures" "live-deployed-template-20260919.yaml"
    $BaselineText = [System.IO.File]::ReadAllText($FixturePath) -replace "`r`n", "`n"

    It "passes on the real reviewed H2 candidate (H2BundleId/H2DiscordMonitorSha256 confirmed absent from PatriotPotInstanceV2)" {
        $patched = Add-H2TemplatePatch $BaselineText
        { Assert-H2BundleIdNotInInstanceSubtree $patched } | Should Not Throw
    }

    It "fails closed if H2BundleId leaks into PatriotPotInstanceV2's subtree" {
        $patched = Add-H2TemplatePatch $BaselineText
        # Simulate the exact hazard this function exists to catch: someone
        # (accidentally) wires H2BundleId into UserData.
        $contaminated = $patched -replace (
            [regex]::Escape('AWS::EC2::Instance')
        ), "AWS::EC2::Instance`n      # planted for the test: `${H2BundleId}"
        { Assert-H2BundleIdNotInInstanceSubtree $contaminated } | Should Throw "H2BundleId"
    }

    It "fails closed if H2DiscordMonitorSha256 leaks into PatriotPotInstanceV2's subtree" {
        $patched = Add-H2TemplatePatch $BaselineText
        $contaminated = $patched -replace (
            [regex]::Escape('AWS::EC2::Instance')
        ), "AWS::EC2::Instance`n      # planted for the test: `${H2DiscordMonitorSha256}"
        { Assert-H2BundleIdNotInInstanceSubtree $contaminated } | Should Throw "H2DiscordMonitorSha256"
    }

    It "does not false-positive on the unrelated, frozen BootstrapBundleId that legitimately remains in PatriotPotInstanceV2's UserData" {
        # BootstrapBundleId is UserData's own bundle parameter (per
        # New-ReviewedChangeSet's requireInstanceReplacement logic).
        # FirewallBundleId/DiscordMonitorSha256, by contrast, belong to the
        # SEPARATE PatriotPotEgressFirewallAssociation and
        # PatriotPotDiscordMonitorAssociation resources (both
        # AWS::SSM::Association, no replacement semantics) -- confirmed
        # here directly with the real Get-ResourceSubtreeText, not assumed.
        $patched = Add-H2TemplatePatch $BaselineText
        $instanceSubtree = Get-ResourceSubtreeText $patched "PatriotPotInstanceV2"
        ($instanceSubtree -match [regex]::Escape('${BootstrapBundleId}')) | Should Be $true
        ($instanceSubtree -match [regex]::Escape('${FirewallBundleId}')) | Should Be $false
        ($instanceSubtree -match [regex]::Escape('${DiscordMonitorSha256}')) | Should Be $false
        { Assert-H2BundleIdNotInInstanceSubtree $patched } | Should Not Throw
    }
}
