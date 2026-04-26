using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Services;
using FirewallRuleToolkit.Domain.Services.Results;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;

namespace FirewallRuleToolkit.Tests.App;

[Collection("ProgramLogger")]
public sealed class MergeUseCaseTests
{
    [Fact]
    public void Execute_WritesNonAllowPoliciesFromAtomicPolicies()
    {
        var written = new List<MergedSecurityPolicy>();

        var exitCode = ExecuteMerge(
            [
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 167772161, Finish = 167772161 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 167772162, Finish = 167772162 },
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
                    Action = SecurityPolicyAction.Deny,
                    GroupId = "group-10",
                    OriginalIndex = 10,
                    OriginalPolicyName = "deny-policy"
                },
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 167772161, Finish = 167772161 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 167772163, Finish = 167772163 },
                    Application = "any",
                    Service = new ServiceValue
                    {
                        ProtocolStart = 6,
                        ProtocolFinish = 6,
                        SourcePortStart = 0,
                        SourcePortFinish = 65535,
                        DestinationPortStart = 443,
                        DestinationPortFinish = 443,
                        Kind = "service"
                    },
                    Action = SecurityPolicyAction.Deny,
                    GroupId = "group-10",
                    OriginalIndex = 10,
                    OriginalPolicyName = "deny-policy"
                }
            ],
            written);

        Assert.Equal(0, exitCode);

        var deny = Assert.Single(written);
        Assert.Equal(SecurityPolicyAction.Deny, deny.Action);
        Assert.Equal((uint)10, deny.MinimumIndex);
        Assert.Equal((uint)10, deny.MaximumIndex);
        Assert.Equal(
            [167772162u, 167772163u],
            deny.DestinationAddresses.Select(address => address.Start).OrderBy(static value => value));
        Assert.Equal(
            [80u, 443u],
            deny.Services.Select(service => service.DestinationPortStart).OrderBy(static value => value));
        Assert.Contains("deny-policy", deny.OriginalPolicyNames);
    }

    [Fact]
    public void Execute_DoesNotMergeNonAllowAtomicPoliciesFromDifferentSourceRules()
    {
        var written = new List<MergedSecurityPolicy>();

        var exitCode = ExecuteMerge(
            [
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 167772161, Finish = 167772161 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 167772162, Finish = 167772162 },
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
                    Action = SecurityPolicyAction.Deny,
                    GroupId = "group-30",
                    OriginalIndex = 30,
                    OriginalPolicyName = "deny-atomic"
                },
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 167772161, Finish = 167772161 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 167772163, Finish = 167772163 },
                    Application = "any",
                    Service = new ServiceValue
                    {
                        ProtocolStart = 6,
                        ProtocolFinish = 6,
                        SourcePortStart = 0,
                        SourcePortFinish = 65535,
                        DestinationPortStart = 443,
                        DestinationPortFinish = 443,
                        Kind = "service"
                    },
                    Action = SecurityPolicyAction.Deny,
                    GroupId = "group-30",
                    OriginalIndex = 31,
                    OriginalPolicyName = "deny-atomic-2"
                }
            ],
            written);

        Assert.Equal(0, exitCode);
        Assert.Equal(2, written.Count);
        Assert.Equal(
            [30U, 31U],
            written.Select(policy => policy.MinimumIndex).OrderBy(static value => value));
        Assert.Equal(
            ["deny-atomic", "deny-atomic-2"],
            written.SelectMany(policy => policy.OriginalPolicyNames).OrderBy(static name => name));
    }

    [Fact]
    public void Execute_RemovesAllowAtomicPolicyShadowedByEarlierDenyPolicy()
    {
        var written = new List<MergedSecurityPolicy>();

        var exitCode = ExecuteMerge(
            [
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 167772160, Finish = 167772415 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 167772162, Finish = 167772162 },
                    Application = "any",
                    Service = new ServiceValue
                    {
                        ProtocolStart = 6,
                        ProtocolFinish = 6,
                        SourcePortStart = 0,
                        SourcePortFinish = 65535,
                        DestinationPortStart = 80,
                        DestinationPortFinish = 90,
                        Kind = "service"
                    },
                    Action = SecurityPolicyAction.Deny,
                    GroupId = "group-deny",
                    OriginalIndex = 10,
                    OriginalPolicyName = "deny-policy"
                },
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 167772161, Finish = 167772161 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 167772162, Finish = 167772162 },
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
                    GroupId = "group-allow",
                    OriginalIndex = 11,
                    OriginalPolicyName = "allow-policy"
                }
            ],
            written);

        Assert.Equal(0, exitCode);

        var merged = Assert.Single(written);
        Assert.Equal(SecurityPolicyAction.Deny, merged.Action);
        Assert.Contains("deny-policy", merged.OriginalPolicyNames);
        Assert.Contains("allow-policy", merged.OriginalPolicyNames);
    }

    [Fact]
    public void Execute_RemovesShadowedAtomicPoliciesBeforeMerge()
    {
        var written = new List<MergedSecurityPolicy>();

        var exitCode = ExecuteMerge(
            [
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 1, Finish = 10 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 100, Finish = 110 },
                    Application = "any",
                    Service = new ServiceValue
                    {
                        ProtocolStart = 6,
                        ProtocolFinish = 6,
                        SourcePortStart = 0,
                        SourcePortFinish = 65535,
                        DestinationPortStart = 80,
                        DestinationPortFinish = 90,
                        Kind = "service"
                    },
                    Action = SecurityPolicyAction.Allow,
                    GroupId = "group-shadow",
                    OriginalIndex = 10,
                    OriginalPolicyName = "front-policy"
                },
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 3, Finish = 3 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 105, Finish = 105 },
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
                    GroupId = "group-shadow",
                    OriginalIndex = 11,
                    OriginalPolicyName = "shadowed-policy"
                }
            ],
            written);

        Assert.Equal(0, exitCode);

        var merged = Assert.Single(written);
        Assert.Equal((uint)10, merged.MinimumIndex);
        Assert.Equal((uint)11, merged.MaximumIndex);
        Assert.Equal(["front-policy", "shadowed-policy"], merged.OriginalPolicyNames.OrderBy(static name => name));
    }

    [Fact]
    public void Execute_UsesEarlierActionWhenLaterPolicyIsFullyShadowed()
    {
        var written = new List<MergedSecurityPolicy>();

        var exitCode = ExecuteMerge(
            [
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 167772160, Finish = 167772415 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 167772164, Finish = 167772164 },
                    Application = "any",
                    Service = new ServiceValue
                    {
                        ProtocolStart = 6,
                        ProtocolFinish = 6,
                        SourcePortStart = 0,
                        SourcePortFinish = 65535,
                        DestinationPortStart = 443,
                        DestinationPortFinish = 450,
                        Kind = "service"
                    },
                    Action = SecurityPolicyAction.Allow,
                    GroupId = "group-allow",
                    OriginalIndex = 20,
                    OriginalPolicyName = "allow-atomic"
                }
                ,
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 167772163, Finish = 167772163 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 167772164, Finish = 167772164 },
                    Application = "web-browsing",
                    Service = new ServiceValue
                    {
                        ProtocolStart = 6,
                        ProtocolFinish = 6,
                        SourcePortStart = 0,
                        SourcePortFinish = 65535,
                        DestinationPortStart = 443,
                        DestinationPortFinish = 443,
                        Kind = "service"
                    },
                    Action = SecurityPolicyAction.Deny,
                    GroupId = "group-deny",
                    OriginalIndex = 21,
                    OriginalPolicyName = "deny-atomic"
                }
            ],
            written);

        Assert.Equal(0, exitCode);

        var merged = Assert.Single(written);
        Assert.Equal(SecurityPolicyAction.Allow, merged.Action);
        Assert.Equal((uint)20, merged.MinimumIndex);
        Assert.Equal((uint)21, merged.MaximumIndex);
        Assert.Equal(["allow-atomic", "deny-atomic"], merged.OriginalPolicyNames.OrderBy(static name => name));
    }

    [Fact]
    public void FindActionRangeOverlaps_WhenDifferentActionsOverlap_ReturnsConflict()
    {
        var overlaps = SecurityPolicyMergeRunner.FindActionRangeOverlaps(
        [
            new SecurityPolicyMergeRunResult.MergeIndexRange(SecurityPolicyAction.Allow, 10, 20),
            new SecurityPolicyMergeRunResult.MergeIndexRange(SecurityPolicyAction.Deny, 15, 25)
        ]);

        var overlap = Assert.Single(overlaps);
        Assert.Equal(SecurityPolicyAction.Allow, overlap.Left.Action);
        Assert.Equal((uint)10, overlap.Left.MinimumIndex);
        Assert.Equal((uint)20, overlap.Left.MaximumIndex);
        Assert.Equal(SecurityPolicyAction.Deny, overlap.Right.Action);
        Assert.Equal((uint)15, overlap.Right.MinimumIndex);
        Assert.Equal((uint)25, overlap.Right.MaximumIndex);
    }

    [Fact]
    public void FindActionRangeOverlaps_WhenActionsAreSame_ReturnsEmpty()
    {
        var overlaps = SecurityPolicyMergeRunner.FindActionRangeOverlaps(
        [
            new SecurityPolicyMergeRunResult.MergeIndexRange(SecurityPolicyAction.Allow, 10, 20),
            new SecurityPolicyMergeRunResult.MergeIndexRange(SecurityPolicyAction.Allow, 15, 25)
        ]);

        Assert.Empty(overlaps);
    }

    [Fact]
    public void FindActionRangeOverlaps_WhenRangesDoNotOverlap_ReturnsEmpty()
    {
        var overlaps = SecurityPolicyMergeRunner.FindActionRangeOverlaps(
        [
            new SecurityPolicyMergeRunResult.MergeIndexRange(SecurityPolicyAction.Allow, 10, 20),
            new SecurityPolicyMergeRunResult.MergeIndexRange(SecurityPolicyAction.Deny, 21, 30)
        ]);

        Assert.Empty(overlaps);
    }

    [Fact]
    public void FindActionRangeOverlaps_WhenOneRangeFullyContainsAnother_ReturnsConflict()
    {
        var overlaps = SecurityPolicyMergeRunner.FindActionRangeOverlaps(
        [
            new SecurityPolicyMergeRunResult.MergeIndexRange(SecurityPolicyAction.Drop, 10, 40),
            new SecurityPolicyMergeRunResult.MergeIndexRange(SecurityPolicyAction.ResetBoth, 20, 30)
        ]);

        var overlap = Assert.Single(overlaps);
        Assert.Equal(SecurityPolicyAction.Drop, overlap.Left.Action);
        Assert.Equal(SecurityPolicyAction.ResetBoth, overlap.Right.Action);
    }

    private static int ExecuteMerge(
        IEnumerable<AtomicSecurityPolicy> atomicPolicies,
        List<MergedSecurityPolicy> written)
    {
        var source = new TestAtomicPolicyMergeSource(atomicPolicies);
        var writeSession = new TestWriteRepositorySession();

        var exitCode = MergeUseCase.Execute(
            source,
            writeSession,
            highSimilarityPercentThreshold: 80);

        written.AddRange(writeSession.MergedSecurityPoliciesRepository.Items);
        return exitCode;
    }
}
