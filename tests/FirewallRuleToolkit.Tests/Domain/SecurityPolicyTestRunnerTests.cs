using FirewallRuleToolkit.Domain.Services;
using FirewallRuleToolkit.Domain.Services.Results;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class SecurityPolicyTestRunnerTests
{
    [Fact]
    public void Run_WhenContainedAndActionMatches_ReturnsNoFindings()
    {
        var runner = new SecurityPolicyTestRunner();
        var findings = new List<SecurityPolicyTestRunner.Finding>();

        var result = runner.Run(
            [CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web")],
            [CreateMergedPolicy(minimumIndex: 10, maximumIndex: 10)],
            findings.Add);

        Assert.Equal(1, result.ProcessedAtomicCount);
        Assert.Equal(1, result.NonShadowedAtomicCount);
        Assert.Equal(0, result.ShadowedAtomicCount);
        Assert.Equal(0, result.WarningCount);
        Assert.Equal(0, result.InformationalCount);
        Assert.Empty(findings);
    }

    [Fact]
    public void Run_WhenMergedApplicationIsAny_ContainsSpecificAtomicApplication()
    {
        var runner = new SecurityPolicyTestRunner();
        var findings = new List<SecurityPolicyTestRunner.Finding>();

        var result = runner.Run(
            [CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web", application: "web-browsing")],
            [CreateMergedPolicy(minimumIndex: 10, maximumIndex: 10, application: "any")],
            findings.Add);

        Assert.Equal(1, result.ProcessedAtomicCount);
        Assert.Equal(1, result.NonShadowedAtomicCount);
        Assert.Equal(0, result.ShadowedAtomicCount);
        Assert.Equal(0, result.WarningCount);
        Assert.Equal(0, result.InformationalCount);
        Assert.Empty(findings);
    }

    [Fact]
    public void Run_WhenMergedAddressRangesContainAtomicAddresses_ReturnsNoFindings()
    {
        var runner = new SecurityPolicyTestRunner();
        var findings = new List<SecurityPolicyTestRunner.Finding>();

        var result = runner.Run(
            [CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web", sourceStart: 3, destinationStart: 105)],
            [CreateMergedPolicy(
                minimumIndex: 10,
                maximumIndex: 10,
                sourceStart: 1,
                sourceFinish: 10,
                destinationStart: 100,
                destinationFinish: 110)],
            findings.Add);

        Assert.Equal(1, result.ProcessedAtomicCount);
        Assert.Equal(1, result.NonShadowedAtomicCount);
        Assert.Equal(0, result.ShadowedAtomicCount);
        Assert.Equal(0, result.WarningCount);
        Assert.Equal(0, result.InformationalCount);
        Assert.Empty(findings);
    }

    [Fact]
    public void Run_WhenMergedServiceRangeContainsAtomicService_ReturnsNoFindings()
    {
        var runner = new SecurityPolicyTestRunner();
        var findings = new List<SecurityPolicyTestRunner.Finding>();

        var result = runner.Run(
            [CreateAtomicPolicy(
                originalIndex: 10,
                originalPolicyName: "allow-web",
                destinationPortStart: 80,
                destinationPortFinish: 80)],
            [CreateMergedPolicy(
                minimumIndex: 10,
                maximumIndex: 10,
                destinationPortStart: 80,
                destinationPortFinish: 90)],
            findings.Add);

        Assert.Equal(1, result.ProcessedAtomicCount);
        Assert.Equal(1, result.NonShadowedAtomicCount);
        Assert.Equal(0, result.ShadowedAtomicCount);
        Assert.Equal(0, result.WarningCount);
        Assert.Equal(0, result.InformationalCount);
        Assert.Empty(findings);
    }

    [Fact]
    public void Run_WhenNoContainingMergedPolicyForNonShadowedAtomic_ReportsWarningFinding()
    {
        var runner = new SecurityPolicyTestRunner();
        var findings = new List<SecurityPolicyTestRunner.Finding>();

        var result = runner.Run(
            [CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web")],
            [CreateMergedPolicy(minimumIndex: 20, maximumIndex: 20, sourceStart: 999)],
            findings.Add);

        Assert.Equal(1, result.ProcessedAtomicCount);
        Assert.Equal(1, result.NonShadowedAtomicCount);
        Assert.Equal(0, result.ShadowedAtomicCount);
        Assert.Equal(1, result.WarningCount);
        Assert.Equal(0, result.InformationalCount);

        var finding = Assert.Single(findings);
        Assert.False(finding.IsShadowed);
        Assert.Equal(SecurityPolicyTestRunner.FindingKind.MissingContainingMergedPolicy, finding.Kind);
        Assert.Null(finding.MatchedMergedPolicy);
        Assert.Equal((ulong)10, finding.AtomicPolicy.OriginalIndex);
    }

    [Fact]
    public void Run_WhenActionDiffersForNonShadowedAtomic_ReportsWarningFinding()
    {
        var runner = new SecurityPolicyTestRunner();
        var findings = new List<SecurityPolicyTestRunner.Finding>();

        var result = runner.Run(
            [CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web", action: SecurityPolicyAction.Allow)],
            [CreateMergedPolicy(minimumIndex: 10, maximumIndex: 10, action: SecurityPolicyAction.Deny)],
            findings.Add);

        Assert.Equal(1, result.WarningCount);
        Assert.Equal(0, result.InformationalCount);

        var finding = Assert.Single(findings);
        Assert.False(finding.IsShadowed);
        Assert.Equal(SecurityPolicyTestRunner.FindingKind.ActionMismatch, finding.Kind);
        Assert.NotNull(finding.MatchedMergedPolicy);
        Assert.Equal(SecurityPolicyAction.Deny, finding.MatchedMergedPolicy?.Action);
    }

    [Fact]
    public void Run_WhenShadowedAtomicIsCoveredByMergedAnyApplication_ReturnsNoFindings()
    {
        var runner = new SecurityPolicyTestRunner();
        var findings = new List<SecurityPolicyTestRunner.Finding>();

        var result = runner.Run(
        [
            CreateAtomicPolicy(
                originalIndex: 10,
                originalPolicyName: "front-policy",
                action: SecurityPolicyAction.Allow,
                application: "any",
                sourceStart: 1,
                sourceFinish: 10,
                destinationStart: 100,
                destinationFinish: 100,
                destinationPortStart: 80,
                destinationPortFinish: 90),
            CreateAtomicPolicy(
                originalIndex: 11,
                originalPolicyName: "shadowed-policy",
                action: SecurityPolicyAction.Allow,
                application: "web-browsing",
                sourceStart: 3,
                sourceFinish: 3,
                destinationStart: 100,
                destinationFinish: 100,
                destinationPortStart: 80,
                destinationPortFinish: 80)
        ],
        [
            CreateMergedPolicy(
                minimumIndex: 10,
                maximumIndex: 11,
                action: SecurityPolicyAction.Allow,
                application: "any",
                sourceStart: 1,
                sourceFinish: 10,
                destinationStart: 100,
                destinationFinish: 100,
                destinationPortStart: 80,
                destinationPortFinish: 90)
        ],
        findings.Add);

        Assert.Equal(2, result.ProcessedAtomicCount);
        Assert.Equal(1, result.NonShadowedAtomicCount);
        Assert.Equal(1, result.ShadowedAtomicCount);
        Assert.Equal(0, result.WarningCount);
        Assert.Equal(0, result.InformationalCount);
        Assert.Empty(findings);
    }

    [Fact]
    public void Run_WhenMultipleMergedPoliciesContainAtomic_UsesFirstHitAfterMinimumThenMaximumSort()
    {
        var runner = new SecurityPolicyTestRunner();
        var findings = new List<SecurityPolicyTestRunner.Finding>();

        var result = runner.Run(
            [CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web", action: SecurityPolicyAction.Allow)],
        [
            CreateMergedPolicy(
                minimumIndex: 10,
                maximumIndex: 30,
                action: SecurityPolicyAction.Deny),
            CreateMergedPolicy(
                minimumIndex: 10,
                maximumIndex: 20,
                action: SecurityPolicyAction.Allow)
        ],
            findings.Add);

        Assert.Equal(0, result.WarningCount);
        Assert.Equal(0, result.InformationalCount);
        Assert.Empty(findings);
    }

    [Fact]
    public void Run_WhenProcessedCountReachesInterval_ReportsProgressEvery2000AtomicPolicies()
    {
        var runner = new SecurityPolicyTestRunner();
        var reportedCounts = new List<long>();

        var atomicPolicies = Enumerable.Range(1, 4500)
            .Select(index => CreateAtomicPolicy(
                originalIndex: (ulong)index,
                originalPolicyName: $"policy-{index}",
                sourceStart: (uint)index,
                sourceFinish: (uint)index,
                destinationStart: (uint)(100000 + index),
                destinationFinish: (uint)(100000 + index)))
            .ToArray();
        var mergedPolicies = atomicPolicies
            .Select(policy => CreateMergedPolicy(
                minimumIndex: policy.OriginalIndex,
                maximumIndex: policy.OriginalIndex,
                action: policy.Action,
                application: policy.Application,
                sourceStart: policy.SourceAddress.Start,
                sourceFinish: policy.SourceAddress.Finish,
                destinationStart: policy.DestinationAddress.Start,
                destinationFinish: policy.DestinationAddress.Finish,
                destinationPortStart: policy.Service.DestinationPortStart,
                destinationPortFinish: policy.Service.DestinationPortFinish))
            .ToArray();

        var result = runner.Run(
            atomicPolicies,
            mergedPolicies,
            reportProgress: reportedCounts.Add);

        Assert.Equal(4500, result.ProcessedAtomicCount);
        Assert.Equal([2000L, 4000L], reportedCounts);
    }

    private static AtomicSecurityPolicy CreateAtomicPolicy(
        ulong originalIndex,
        string originalPolicyName,
        SecurityPolicyAction action = SecurityPolicyAction.Allow,
        string application = "web-browsing",
        string fromZone = "trust",
        string toZone = "untrust",
        uint sourceStart = 1,
        uint sourceFinish = 1,
        uint destinationStart = 100,
        uint destinationFinish = 100,
        uint destinationPortStart = 80,
        uint destinationPortFinish = 80,
        string? serviceKind = "service")
    {
        return new AtomicSecurityPolicy
        {
            FromZone = fromZone,
            SourceAddress = new AddressValue { Start = sourceStart, Finish = sourceFinish },
            ToZone = toZone,
            DestinationAddress = new AddressValue { Start = destinationStart, Finish = destinationFinish },
            Application = application,
            Service = new ServiceValue
            {
                ProtocolStart = 6,
                ProtocolFinish = 6,
                SourcePortStart = 0,
                SourcePortFinish = 65535,
                DestinationPortStart = destinationPortStart,
                DestinationPortFinish = destinationPortFinish,
                Kind = serviceKind
            },
            Action = action,
            GroupId = "group-1",
            OriginalIndex = originalIndex,
            OriginalPolicyName = originalPolicyName
        };
    }

    private static MergedSecurityPolicy CreateMergedPolicy(
        ulong minimumIndex,
        ulong maximumIndex,
        SecurityPolicyAction action = SecurityPolicyAction.Allow,
        string application = "web-browsing",
        string fromZone = "trust",
        string toZone = "untrust",
        uint sourceStart = 1,
        uint sourceFinish = 1,
        uint destinationStart = 100,
        uint destinationFinish = 100,
        uint destinationPortStart = 80,
        uint destinationPortFinish = 80,
        string? serviceKind = "service")
    {
        return new MergedSecurityPolicy
        {
            FromZones = new HashSet<string>(StringComparer.Ordinal) { fromZone },
            SourceAddresses = [new AddressValue { Start = sourceStart, Finish = sourceFinish }],
            ToZones = new HashSet<string>(StringComparer.Ordinal) { toZone },
            DestinationAddresses = [new AddressValue { Start = destinationStart, Finish = destinationFinish }],
            Applications = new HashSet<string>(StringComparer.Ordinal) { application },
            Services =
            [
                new ServiceValue
                {
                    ProtocolStart = 6,
                    ProtocolFinish = 6,
                    SourcePortStart = 0,
                    SourcePortFinish = 65535,
                    DestinationPortStart = destinationPortStart,
                    DestinationPortFinish = destinationPortFinish,
                    Kind = serviceKind
                }
            ],
            Action = action,
            GroupId = "group-merged",
            MinimumIndex = minimumIndex,
            MaximumIndex = maximumIndex,
            OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { $"merged-{minimumIndex}" }
        };
    }
}
