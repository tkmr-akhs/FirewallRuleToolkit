using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;

namespace FirewallRuleToolkit.Tests.App;

[Collection("ProgramLogger")]
public sealed class MergeUseCaseProgressTests
{
    [Fact]
    public void Execute_WhenProcessedCountReachesInterval_ReportsProgressEvery2000AtomicPolicies()
    {
        var reportedCounts = new List<long>();
        var source = new TestAtomicPolicyMergeSource(Enumerable.Range(1, 4500).Select(CreateAtomicPolicy));
        var writeSession = new TestWriteRepositorySession();

        var exitCode = MergeUseCase.Execute(
            source,
            writeSession,
            highSimilarityPercentThreshold: 80,
            reportProgress: reportedCounts.Add);

        Assert.Equal(0, exitCode);
        Assert.Equal([2000L, 4000L], reportedCounts);
        Assert.NotEmpty(writeSession.MergedSecurityPoliciesRepository.Items);
    }

    private static AtomicSecurityPolicy CreateAtomicPolicy(int index)
    {
        return new AtomicSecurityPolicy
        {
            FromZone = "trust",
            SourceAddress = new AddressValue { Start = (uint)index, Finish = (uint)index },
            ToZone = "untrust",
            DestinationAddress = new AddressValue { Start = (uint)(100000 + index), Finish = (uint)(100000 + index) },
            Application = "any",
            Service = new ServiceValue
            {
                ProtocolStart = 6,
                ProtocolFinish = 6,
                SourcePortStart = 0,
                SourcePortFinish = 65535,
                DestinationPortStart = 80,
                DestinationPortFinish = 80,
                Kind = "service"
            },
            Action = SecurityPolicyAction.Allow,
            GroupId = "group-1",
            OriginalIndex = (uint)index,
            OriginalPolicyName = $"policy-{index}"
        };
    }
}
