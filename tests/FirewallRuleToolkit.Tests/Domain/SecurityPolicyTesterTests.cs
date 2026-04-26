using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.Services;
using FirewallRuleToolkit.Domain.ValueObjects;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class SecurityPolicyTesterTests
{
    [Fact]
    public void Test_WhenMergedApplicationIsAny_ReturnsMatch()
    {
        var tester = new SecurityPolicyTester();

        var result = tester.Test(
            CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web", application: "web-browsing"),
            [CreateMergedPolicy(minimumIndex: 10, maximumIndex: 10, application: "any")]);

        Assert.True(result.IsMatch);
        Assert.NotNull(result.MatchedMergedPolicy);
        Assert.Null(result.FindingKind);
    }

    [Fact]
    public void Test_WhenMergedApplicationIsUppercaseAny_ReturnsMatch()
    {
        var tester = new SecurityPolicyTester();

        var result = tester.Test(
            CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web", application: "web-browsing"),
            [CreateMergedPolicy(minimumIndex: 10, maximumIndex: 10, application: "ANY")]);

        Assert.True(result.IsMatch);
        Assert.NotNull(result.MatchedMergedPolicy);
        Assert.Null(result.FindingKind);
    }

    [Fact]
    public void Test_WhenMergedRangesContainAtomic_ReturnsMatch()
    {
        var tester = new SecurityPolicyTester();

        var result = tester.Test(
            CreateAtomicPolicy(
                originalIndex: 10,
                originalPolicyName: "allow-web",
                sourceStart: 3,
                destinationStart: 105,
                destinationPortStart: 80,
                destinationPortFinish: 80),
            [
                CreateMergedPolicy(
                    minimumIndex: 10,
                    maximumIndex: 10,
                    sourceStart: 1,
                    sourceFinish: 10,
                    destinationStart: 100,
                    destinationFinish: 110,
                    destinationPortStart: 80,
                    destinationPortFinish: 90)
            ]);

        Assert.True(result.IsMatch);
        Assert.NotNull(result.MatchedMergedPolicy);
        Assert.Null(result.FindingKind);
    }

    [Fact]
    public void Test_WhenActionDiffers_ReturnsActionMismatch()
    {
        var tester = new SecurityPolicyTester();

        var result = tester.Test(
            CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web", action: SecurityPolicyAction.Allow),
            [CreateMergedPolicy(minimumIndex: 10, maximumIndex: 10, action: SecurityPolicyAction.Deny)]);

        Assert.False(result.IsMatch);
        Assert.Equal(SecurityPolicyTestRunner.FindingKind.ActionMismatch, result.FindingKind);
        Assert.NotNull(result.MatchedMergedPolicy);
    }

    [Fact]
    public void Test_WhenNoContainingMergedPolicy_ReturnsMissingContainingMergedPolicy()
    {
        var tester = new SecurityPolicyTester();

        var result = tester.Test(
            CreateAtomicPolicy(originalIndex: 10, originalPolicyName: "allow-web"),
            [CreateMergedPolicy(minimumIndex: 20, maximumIndex: 20, sourceStart: 999)]);

        Assert.False(result.IsMatch);
        Assert.Equal(SecurityPolicyTestRunner.FindingKind.MissingContainingMergedPolicy, result.FindingKind);
        Assert.Null(result.MatchedMergedPolicy);
    }

    private static AtomicSecurityPolicy CreateAtomicPolicy(
        uint originalIndex,
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
        uint minimumIndex,
        uint maximumIndex,
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
