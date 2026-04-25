using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;

namespace FirewallRuleToolkit.Tests.App;

[Collection("ProgramLogger")]
public sealed class TestUseCaseProgressTests
{
    [Fact]
    public void Execute_WhenProcessedCountReachesInterval_ReportsProgressEvery2000AtomicPolicies()
    {
        var atomicPolicies = Enumerable.Range(1, 4500)
            .Select(CreateAtomicPolicy)
            .ToArray();
        var mergedPolicies = atomicPolicies
            .Select(CreateMergedPolicy)
            .ToArray();

        var reportedCounts = new List<long>();
        var source = new TestAtomicPolicyMergeSource(atomicPolicies);
        var merged = new TestReadRepository<MergedSecurityPolicy>(mergedPolicies);

        var exitCode = TestUseCase.Execute(
            source,
            merged,
            reportProgress: reportedCounts.Add);

        Assert.Equal(0, exitCode);
        Assert.Equal([2000L, 4000L], reportedCounts);
    }

    private static AtomicSecurityPolicy CreateAtomicPolicy(int index)
    {
        return new AtomicSecurityPolicy
        {
            FromZone = "trust",
            SourceAddress = new AddressValue { Start = (uint)index, Finish = (uint)index },
            ToZone = "untrust",
            DestinationAddress = new AddressValue { Start = (uint)(100000 + index), Finish = (uint)(100000 + index) },
            Application = "web-browsing",
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
            OriginalIndex = (ulong)index,
            OriginalPolicyName = $"policy-{index}"
        };
    }

    private static MergedSecurityPolicy CreateMergedPolicy(AtomicSecurityPolicy atomicPolicy)
    {
        return new MergedSecurityPolicy
        {
            FromZones = new HashSet<string>(StringComparer.Ordinal) { atomicPolicy.FromZone },
            SourceAddresses = [atomicPolicy.SourceAddress],
            ToZones = new HashSet<string>(StringComparer.Ordinal) { atomicPolicy.ToZone },
            DestinationAddresses = [atomicPolicy.DestinationAddress],
            Applications = new HashSet<string>(StringComparer.Ordinal) { atomicPolicy.Application },
            Services = [atomicPolicy.Service],
            Action = atomicPolicy.Action,
            GroupId = "group-merged",
            MinimumIndex = atomicPolicy.OriginalIndex,
            MaximumIndex = atomicPolicy.OriginalIndex,
            OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { atomicPolicy.OriginalPolicyName }
        };
    }
}
