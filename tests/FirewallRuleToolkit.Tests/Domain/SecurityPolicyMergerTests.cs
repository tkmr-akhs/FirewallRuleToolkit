using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Services;
using FirewallRuleToolkit.Domain.Services.Merging;
using FirewallRuleToolkit.Config;
using FirewallRuleToolkit.Logging;
using Microsoft.Extensions.Logging;

namespace FirewallRuleToolkit.Tests.Domain;

[Collection("ProgramLogger")]
public sealed class SecurityPolicyMergerTests
{
    [Fact]
    public void MergePartition_WhenProtocolDiffersAndPortsDiffer_StillMergesByProtocolPass()
    {
        var merger = new SecurityPolicyMerger(80);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 10,
                originalPolicyName: "tcp-rule",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80),
            CreateAtomicPolicy(
                originalIndex: 11,
                originalPolicyName: "udp-rule",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 53,
                destinationPortFinish: 53)
        };

        var merged = merger.MergePartition(source);

        var policy = Assert.Single(merged);
        Assert.Equal((ulong)10, policy.MinimumIndex);
        Assert.Equal((ulong)11, policy.MaximumIndex);
        Assert.Equal(2, policy.Services.Count);
        Assert.Contains("tcp-rule", policy.OriginalPolicyNames);
        Assert.Contains("udp-rule", policy.OriginalPolicyNames);
    }

    [Fact]
    public void MergePartition_WhenGroupIdIsEmpty_KeepsEmptyGroupId()
    {
        var merger = new SecurityPolicyMerger(80);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 12,
                originalPolicyName: "empty-group-tcp",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                groupId: string.Empty),
            CreateAtomicPolicy(
                originalIndex: 13,
                originalPolicyName: "empty-group-udp",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 53,
                destinationPortFinish: 53,
                groupId: string.Empty)
        };

        var merged = merger.MergePartition(source);

        var policy = Assert.Single(merged);
        Assert.Equal(string.Empty, policy.GroupId);
        Assert.Equal(2, policy.Services.Count);
        Assert.Equal(["empty-group-tcp", "empty-group-udp"], policy.OriginalPolicyNames.OrderBy(value => value));
    }

    [Fact]
    public void MergePartition_WhenActionDiffers_DoesNotMerge()
    {
        var merger = new SecurityPolicyMerger(80);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 20,
                originalPolicyName: "allow-rule",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                action: SecurityPolicyAction.Allow),
            CreateAtomicPolicy(
                originalIndex: 21,
                originalPolicyName: "deny-rule",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 53,
                destinationPortFinish: 53,
                action: SecurityPolicyAction.Deny)
        };

        var merged = merger.MergePartition(source);

        Assert.Equal(2, merged.Count);
    }

    [Fact]
    public void MergePartition_WhenNonAllowPoliciesShareSameSourceRule_MergesOnlyThatRule()
    {
        var merger = new SecurityPolicyMerger(80);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 25,
                originalPolicyName: "deny-rule",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                action: SecurityPolicyAction.Deny),
            CreateAtomicPolicy(
                originalIndex: 25,
                originalPolicyName: "deny-rule",
                sourceAddressStart: 101,
                sourceAddressFinish: 101,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 443,
                destinationPortFinish: 443,
                action: SecurityPolicyAction.Deny)
        };

        var merged = merger.MergePartition(source);

        var policy = Assert.Single(merged);
        Assert.Equal(SecurityPolicyAction.Deny, policy.Action);
        Assert.Equal((ulong)25, policy.MinimumIndex);
        Assert.Equal((ulong)25, policy.MaximumIndex);
        Assert.Equal([100u, 101u], policy.SourceAddresses.Select(address => address.Start).OrderBy(value => value));
        Assert.Equal([200u, 201u], policy.DestinationAddresses.Select(address => address.Start).OrderBy(value => value));
        Assert.Equal([6u, 17u], policy.Services.Select(service => service.ProtocolStart).OrderBy(value => value));
        Assert.Equal(["deny-rule"], policy.OriginalPolicyNames.OrderBy(value => value));
    }

    [Fact]
    public void MergePartition_WhenNonAllowPoliciesComeFromDifferentRules_DoesNotAggregate()
    {
        var merger = new SecurityPolicyMerger(80);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 26,
                originalPolicyName: "deny-a",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                action: SecurityPolicyAction.Deny),
            CreateAtomicPolicy(
                originalIndex: 27,
                originalPolicyName: "deny-b",
                sourceAddressStart: 101,
                sourceAddressFinish: 101,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 443,
                destinationPortFinish: 443,
                action: SecurityPolicyAction.Deny)
        };

        var merged = merger.MergePartition(source);

        Assert.Equal(2, merged.Count);
        Assert.All(
            merged,
            static policy =>
            {
                Assert.Single(policy.SourceAddresses);
                Assert.Single(policy.DestinationAddresses);
                Assert.Single(policy.Services);
                Assert.Single(policy.OriginalPolicyNames);
            });
    }

    [Fact]
    public void MergePartition_WhenPortMergeAbsorbsProtocolDifferences_FirstAddressPassStopsAtThreePolicies()
    {
        var merger = new SecurityPolicyMerger(80);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 30,
                originalPolicyName: "a",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80),
            CreateAtomicPolicy(
                originalIndex: 31,
                originalPolicyName: "b",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 53,
                destinationPortFinish: 53),
            CreateAtomicPolicy(
                originalIndex: 32,
                originalPolicyName: "c",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80),
            CreateAtomicPolicy(
                originalIndex: 33,
                originalPolicyName: "d",
                sourceAddressStart: 101,
                sourceAddressFinish: 101,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 53,
                destinationPortFinish: 53)
        };

        var merged = merger.MergePartition(source);

        Assert.Collection(
            merged,
            combinedPolicy =>
            {
                Assert.Equal((ulong)30, combinedPolicy.MinimumIndex);
                Assert.Equal((ulong)31, combinedPolicy.MaximumIndex);
                Assert.Equal([100u], combinedPolicy.SourceAddresses.Select(address => address.Start).OrderBy(value => value));
                Assert.Equal([200u], combinedPolicy.DestinationAddresses.Select(address => address.Start).OrderBy(value => value));
                Assert.Equal([6u, 17u], combinedPolicy.Services.Select(service => service.ProtocolStart).OrderBy(value => value));
                Assert.Equal(["a", "b"], combinedPolicy.OriginalPolicyNames.OrderBy(value => value));
            },
            tcpPolicy =>
            {
                Assert.Equal((ulong)32, tcpPolicy.MinimumIndex);
                Assert.Equal((ulong)32, tcpPolicy.MaximumIndex);
                Assert.Equal([100u], tcpPolicy.SourceAddresses.Select(address => address.Start).OrderBy(value => value));
                Assert.Equal([201u], tcpPolicy.DestinationAddresses.Select(address => address.Start).OrderBy(value => value));
                Assert.Equal([6u], tcpPolicy.Services.Select(service => service.ProtocolStart).OrderBy(value => value));
                Assert.Equal(["c"], tcpPolicy.OriginalPolicyNames.OrderBy(value => value));
            },
            udpPolicy =>
            {
                Assert.Equal((ulong)33, udpPolicy.MinimumIndex);
                Assert.Equal((ulong)33, udpPolicy.MaximumIndex);
                Assert.Equal([101u], udpPolicy.SourceAddresses.Select(address => address.Start).OrderBy(value => value));
                Assert.Equal([200u], udpPolicy.DestinationAddresses.Select(address => address.Start).OrderBy(value => value));
                Assert.Equal([17u], udpPolicy.Services.Select(service => service.ProtocolStart).OrderBy(value => value));
                Assert.Equal(["d"], udpPolicy.OriginalPolicyNames.OrderBy(value => value));
            });
    }

    [Fact]
    public void MergePartition_WhenAddressPassesCreateNewMergeOpportunity_ProducesSingleAggregatedPolicy()
    {
        var merger = new SecurityPolicyMerger(80);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 40,
                originalPolicyName: "a",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80),
            CreateAtomicPolicy(
                originalIndex: 41,
                originalPolicyName: "b",
                sourceAddressStart: 101,
                sourceAddressFinish: 101,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80),
            CreateAtomicPolicy(
                originalIndex: 42,
                originalPolicyName: "c",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80),
            CreateAtomicPolicy(
                originalIndex: 43,
                originalPolicyName: "d",
                sourceAddressStart: 101,
                sourceAddressFinish: 101,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80)
        };

        var merged = merger.MergePartition(source);

        var policy = Assert.Single(merged);
        Assert.Equal((ulong)40, policy.MinimumIndex);
        Assert.Equal((ulong)43, policy.MaximumIndex);
        Assert.Equal([100u, 101u], policy.SourceAddresses.Select(address => address.Start).OrderBy(value => value));
        Assert.Equal([200u, 201u], policy.DestinationAddresses.Select(address => address.Start).OrderBy(value => value));
        Assert.Equal(["a", "b", "c", "d"], policy.OriginalPolicyNames.OrderBy(value => value));
    }

    [Fact]
    public void MergePartition_WhenAllowAnyApplicationContainsSpecificApplication_DeduplicatesToAnyApplication()
    {
        var merger = new SecurityPolicyMerger(80);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 44,
                originalPolicyName: "specific-app",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                application: "web-browsing"),
            CreateAtomicPolicy(
                originalIndex: 45,
                originalPolicyName: "any-app",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                application: "any")
        };

        var merged = merger.MergePartition(source);

        var policy = Assert.Single(merged);
        Assert.Equal((ulong)44, policy.MinimumIndex);
        Assert.Equal((ulong)45, policy.MaximumIndex);
        Assert.Equal(["any"], policy.Applications.OrderBy(value => value));
        Assert.Equal(["any-app", "specific-app"], policy.OriginalPolicyNames.OrderBy(value => value));
    }

    [Fact]
    public void MergePartition_WhenAllowUppercaseAnyApplicationContainsSpecificApplication_DeduplicatesToAnyApplication()
    {
        var merger = new SecurityPolicyMerger(80);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 44,
                originalPolicyName: "specific-app",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                application: "web-browsing"),
            CreateAtomicPolicy(
                originalIndex: 45,
                originalPolicyName: "any-app",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                application: "ANY")
        };

        var merged = merger.MergePartition(source);

        var policy = Assert.Single(merged);
        Assert.Equal((ulong)44, policy.MinimumIndex);
        Assert.Equal((ulong)45, policy.MaximumIndex);
        Assert.Equal(["ANY"], policy.Applications.OrderBy(value => value));
        Assert.Equal(["any-app", "specific-app"], policy.OriginalPolicyNames.OrderBy(value => value));
    }

    [Fact]
    public void MergePartition_WhenOnlyWellKnownDestinationPortsBelowThreshold_DoesNotMergeDestinationAddresses()
    {
        var merger = new SecurityPolicyMerger(
            80,
            new HashSet<uint> { 80, 443 },
            smallWellKnownDestinationPortCountThreshold: 3);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 50,
                originalPolicyName: "http",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 51,
                originalPolicyName: "http-443-a",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 443,
                destinationPortFinish: 443,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 52,
                originalPolicyName: "http-80-b",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 53,
                originalPolicyName: "http-443-b",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 443,
                destinationPortFinish: 443,
                kind: "service")
        };

        var merged = merger.MergePartition(source);

        Assert.Equal(2, merged.Count);
        Assert.All(
            merged,
            static policy =>
            {
                Assert.Equal(2, policy.Services.Count);
                Assert.Single(policy.DestinationAddresses);
            });
        Assert.Equal(
            [200u, 201u],
            merged.SelectMany(policy => policy.DestinationAddresses).Select(address => address.Start).OrderBy(value => value));
    }

    [Fact]
    public void MergePartition_WhenDestinationAddressAggregationIsSkippedByWellKnownPorts_WritesDebugLog()
    {
        var merger = new SecurityPolicyMerger(
            80,
            new HashSet<uint> { 80, 443 },
            smallWellKnownDestinationPortCountThreshold: 3);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 50,
                originalPolicyName: "http",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 51,
                originalPolicyName: "https",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 443,
                destinationPortFinish: 443,
                kind: "service")
        };

        var logText = CaptureDebugLog(logger =>
        {
            var merger = new SecurityPolicyMerger(
                80,
                new HashSet<uint> { 80, 443 },
                smallWellKnownDestinationPortCountThreshold: 3,
                logger: logger);

            merger.MergePartition(source);
        });

        Assert.Contains(
            "merge debug: kept destination addresses separated because services are small well-known destination ports.",
            logText,
            StringComparison.Ordinal);
        Assert.Contains("policyCount=2", logText, StringComparison.Ordinal);
        Assert.Contains("destinationPorts=", logText, StringComparison.Ordinal);
        Assert.Matches("(?s).*destinationPorts=.*80.*443.*", logText);
    }

    [Fact]
    public void MergePartition_WhenOnlyWellKnownDestinationPortsBelowThreshold_StillAggregatesSourceAddresses()
    {
        var merger = new SecurityPolicyMerger(
            80,
            new HashSet<uint> { 80, 443 },
            smallWellKnownDestinationPortCountThreshold: 3);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 60,
                originalPolicyName: "http-a",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 61,
                originalPolicyName: "https-a",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 443,
                destinationPortFinish: 443,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 62,
                originalPolicyName: "http-b",
                sourceAddressStart: 101,
                sourceAddressFinish: 101,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 63,
                originalPolicyName: "https-b",
                sourceAddressStart: 101,
                sourceAddressFinish: 101,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 443,
                destinationPortFinish: 443,
                kind: "service")
        };

        var merged = merger.MergePartition(source);

        var policy = Assert.Single(merged);
        Assert.Equal((ulong)60, policy.MinimumIndex);
        Assert.Equal((ulong)63, policy.MaximumIndex);
        Assert.Equal(2, policy.Services.Count);
        Assert.Equal([100u, 101u], policy.SourceAddresses.Select(address => address.Start).OrderBy(value => value));
    }

    [Fact]
    public void MergePartition_WhenWellKnownDestinationPortCountReachesThreshold_MergesDestinationAddresses()
    {
        var merger = new SecurityPolicyMerger(
            80,
            new HashSet<uint> { 80, 443, 8443 },
            smallWellKnownDestinationPortCountThreshold: 3);
        var source = new[]
        {
            CreateAtomicPolicy(
                originalIndex: 70,
                originalPolicyName: "http",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 71,
                originalPolicyName: "https",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 443,
                destinationPortFinish: 443,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 72,
                originalPolicyName: "alt-https-a",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 200,
                destinationAddressFinish: 200,
                protocol: 132,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 8443,
                destinationPortFinish: 8443,
                kind: "service")
            ,
            CreateAtomicPolicy(
                originalIndex: 73,
                originalPolicyName: "http-b",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 6,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 80,
                destinationPortFinish: 80,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 74,
                originalPolicyName: "https-b",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 17,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 443,
                destinationPortFinish: 443,
                kind: "service"),
            CreateAtomicPolicy(
                originalIndex: 75,
                originalPolicyName: "alt-https-b",
                sourceAddressStart: 100,
                sourceAddressFinish: 100,
                destinationAddressStart: 201,
                destinationAddressFinish: 201,
                protocol: 132,
                sourcePortStart: 1,
                sourcePortFinish: 65535,
                destinationPortStart: 8443,
                destinationPortFinish: 8443,
                kind: "service")
        };

        var merged = merger.MergePartition(source);

        var policy = Assert.Single(merged);
        Assert.Equal(3, policy.Services.Count);
        Assert.Equal((ulong)70, policy.MinimumIndex);
        Assert.Equal((ulong)75, policy.MaximumIndex);
        Assert.Equal([200u, 201u], policy.DestinationAddresses.Select(address => address.Start).OrderBy(value => value));
    }

    [Fact]
    public void RecomposeHighSimilarityPolicies_WhenDestinationAndServiceMeetThreshold_UsesUnionSourcesInCommonPolicy()
    {
        var recomposer = CreateHighSimilarityPolicyRecomposer(80);
        var source = new[]
        {
            CreateMergedPolicy(
                originalIndex: 100,
                originalPolicyName: "left",
                sourceAddresses: [1, 2, 3, 4, 5],
                destinationAddresses: [10, 11, 12, 13, 14],
                destinationPorts: [20, 21, 22, 23, 24]),
            CreateMergedPolicy(
                originalIndex: 200,
                originalPolicyName: "right",
                sourceAddresses: [5, 6, 7, 8, 9],
                destinationAddresses: [11, 12, 13, 14, 15],
                destinationPorts: [21, 22, 23, 24, 25])
        };

        var recomposed = recomposer.Recompose(source);

        Assert.Equal(5, recomposed.Count);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5, 6, 7, 8, 9],
            destinationAddresses: [11, 12, 13, 14],
            destinationPorts: [21, 22, 23, 24],
            minimumIndex: 100,
            maximumIndex: 200,
            originalPolicyNames: ["left", "right"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5],
            destinationAddresses: [10],
            destinationPorts: [20, 21, 22, 23, 24],
            minimumIndex: 100,
            maximumIndex: 100,
            originalPolicyNames: ["left"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5],
            destinationAddresses: [11, 12, 13, 14],
            destinationPorts: [20],
            minimumIndex: 100,
            maximumIndex: 100,
            originalPolicyNames: ["left"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [5, 6, 7, 8, 9],
            destinationAddresses: [15],
            destinationPorts: [21, 22, 23, 24, 25],
            minimumIndex: 200,
            maximumIndex: 200,
            originalPolicyNames: ["right"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [5, 6, 7, 8, 9],
            destinationAddresses: [11, 12, 13, 14],
            destinationPorts: [25],
            minimumIndex: 200,
            maximumIndex: 200,
            originalPolicyNames: ["right"]);
    }

    [Fact]
    public void RecomposeHighSimilarityPolicies_WhenPairIsRecomposed_WritesDebugLog()
    {
        var recomposer = CreateHighSimilarityPolicyRecomposer(80);
        var source = new[]
        {
            CreateMergedPolicy(
                originalIndex: 100,
                originalPolicyName: "left",
                sourceAddresses: [1, 2, 3, 4, 5],
                destinationAddresses: [10, 11, 12, 13, 14],
                destinationPorts: [20, 21, 22, 23, 24]),
            CreateMergedPolicy(
                originalIndex: 200,
                originalPolicyName: "right",
                sourceAddresses: [5, 6, 7, 8, 9],
                destinationAddresses: [11, 12, 13, 14, 15],
                destinationPorts: [21, 22, 23, 24, 25])
        };

        var logText = CaptureDebugLog(logger =>
        {
            var recomposer = CreateHighSimilarityPolicyRecomposer(80, logger: logger);
            recomposer.Recompose(source);
        });

        Assert.Contains(
            "merge debug: selected high-similarity pair.",
            logText,
            StringComparison.Ordinal);
        Assert.Contains("score=8", logText, StringComparison.Ordinal);
        Assert.Contains("unionSources=9", logText, StringComparison.Ordinal);
        Assert.Contains("commonDestinations=4", logText, StringComparison.Ordinal);
        Assert.Contains("commonServices=4", logText, StringComparison.Ordinal);
        Assert.Contains(
            "merge debug: created recomposed policies.",
            logText,
            StringComparison.Ordinal);
        Assert.Contains("residualCount=4", logText, StringComparison.Ordinal);
        Assert.Contains("leftOriginalNames=left", logText, StringComparison.Ordinal);
        Assert.Contains("rightOriginalNames=right", logText, StringComparison.Ordinal);
        Assert.Contains("commonOriginalNames=left,right", logText, StringComparison.Ordinal);
    }

    [Fact]
    public void RecomposeHighSimilarityPolicies_WhenSourceAddressesDoNotOverlap_RecomposesUsingUnionSources()
    {
        var recomposer = CreateHighSimilarityPolicyRecomposer(80);
        var source = new[]
        {
            CreateMergedPolicy(
                originalIndex: 100,
                originalPolicyName: "left",
                sourceAddresses: [1, 2, 3, 4, 5],
                destinationAddresses: [10, 11, 12, 13, 14],
                destinationPorts: [20, 21, 22, 23, 24]),
            CreateMergedPolicy(
                originalIndex: 200,
                originalPolicyName: "right",
                sourceAddresses: [6, 7, 8, 9, 10],
                destinationAddresses: [11, 12, 13, 14, 15],
                destinationPorts: [21, 22, 23, 24, 25])
        };

        var recomposed = recomposer.Recompose(source);

        Assert.Equal(5, recomposed.Count);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            destinationAddresses: [11, 12, 13, 14],
            destinationPorts: [21, 22, 23, 24],
            minimumIndex: 100,
            maximumIndex: 200,
            originalPolicyNames: ["left", "right"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5],
            destinationAddresses: [10],
            destinationPorts: [20, 21, 22, 23, 24],
            minimumIndex: 100,
            maximumIndex: 100,
            originalPolicyNames: ["left"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5],
            destinationAddresses: [11, 12, 13, 14],
            destinationPorts: [20],
            minimumIndex: 100,
            maximumIndex: 100,
            originalPolicyNames: ["left"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [6, 7, 8, 9, 10],
            destinationAddresses: [15],
            destinationPorts: [21, 22, 23, 24, 25],
            minimumIndex: 200,
            maximumIndex: 200,
            originalPolicyNames: ["right"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [6, 7, 8, 9, 10],
            destinationAddresses: [11, 12, 13, 14],
            destinationPorts: [25],
            minimumIndex: 200,
            maximumIndex: 200,
            originalPolicyNames: ["right"]);
    }

    [Fact]
    public void RecomposeHighSimilarityPolicies_WhenCommonPartMatchesNextPolicy_ReusesCommonPartForNextComparison()
    {
        var recomposer = CreateHighSimilarityPolicyRecomposer(80);
        var source = new[]
        {
            CreateMergedPolicy(
                originalIndex: 300,
                originalPolicyName: "a",
                sourceAddresses: [1, 2, 3, 4, 5, 6],
                destinationAddresses: [10, 11, 12, 13, 14, 15],
                destinationPorts: [20, 21, 22, 23, 24, 25]),
            CreateMergedPolicy(
                originalIndex: 400,
                originalPolicyName: "b",
                sourceAddresses: [2, 3, 4, 5, 6, 7],
                destinationAddresses: [11, 12, 13, 14, 15, 16],
                destinationPorts: [21, 22, 23, 24, 25, 26]),
            CreateMergedPolicy(
                originalIndex: 500,
                originalPolicyName: "c",
                sourceAddresses: [2, 3, 4, 5, 8],
                destinationAddresses: [11, 12, 13, 14, 17],
                destinationPorts: [21, 22, 23, 24, 27])
        };

        var recomposed = recomposer.Recompose(source);

        Assert.Equal(9, recomposed.Count);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5, 6, 7, 8],
            destinationAddresses: [11, 12, 13, 14],
            destinationPorts: [21, 22, 23, 24],
            minimumIndex: 300,
            maximumIndex: 500,
            originalPolicyNames: ["a", "b", "c"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5, 6, 7],
            destinationAddresses: [15],
            destinationPorts: [21, 22, 23, 24, 25],
            minimumIndex: 300,
            maximumIndex: 400,
            originalPolicyNames: ["a", "b"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [2, 3, 4, 5, 8],
            destinationAddresses: [17],
            destinationPorts: [21, 22, 23, 24, 27],
            minimumIndex: 500,
            maximumIndex: 500,
            originalPolicyNames: ["c"]);
    }

    [Fact]
    public void RecomposeHighSimilarityPolicies_WhenCommonServicesAreSmallWellKnownPorts_SkipsThatPair()
    {
        var recomposer = CreateHighSimilarityPolicyRecomposer(
            80,
            new HashSet<uint> { 80, 443 },
            smallWellKnownDestinationPortCountThreshold: 3);
        var source = new[]
        {
            CreateMergedPolicy(
                originalIndex: 600,
                originalPolicyName: "left",
                sourceAddresses: [1, 2, 3, 4, 5],
                destinationAddresses: [10, 11, 12, 13, 14],
                destinationPorts: [80, 443]),
            CreateMergedPolicy(
                originalIndex: 700,
                originalPolicyName: "right",
                sourceAddresses: [2, 3, 4, 5, 6],
                destinationAddresses: [11, 12, 13, 14, 15],
                destinationPorts: [80, 443])
        };

        var recomposed = recomposer.Recompose(source);

        Assert.Equal(2, recomposed.Count);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5],
            destinationAddresses: [10, 11, 12, 13, 14],
            destinationPorts: [80, 443],
            minimumIndex: 600,
            maximumIndex: 600,
            originalPolicyNames: ["left"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [2, 3, 4, 5, 6],
            destinationAddresses: [11, 12, 13, 14, 15],
            destinationPorts: [80, 443],
            minimumIndex: 700,
            maximumIndex: 700,
            originalPolicyNames: ["right"]);
    }

    [Fact]
    public void RecomposeHighSimilarityPolicies_WhenPairIsSkippedByWellKnownPorts_WritesDebugLog()
    {
        var recomposer = CreateHighSimilarityPolicyRecomposer(
            80,
            new HashSet<uint> { 80, 443 },
            smallWellKnownDestinationPortCountThreshold: 3);
        var source = new[]
        {
            CreateMergedPolicy(
                originalIndex: 600,
                originalPolicyName: "left",
                sourceAddresses: [1, 2, 3, 4, 5],
                destinationAddresses: [10, 11, 12, 13, 14],
                destinationPorts: [80, 443]),
            CreateMergedPolicy(
                originalIndex: 700,
                originalPolicyName: "right",
                sourceAddresses: [2, 3, 4, 5, 6],
                destinationAddresses: [11, 12, 13, 14, 15],
                destinationPorts: [80, 443])
        };

        var logText = CaptureDebugLog(logger =>
        {
            var recomposer = CreateHighSimilarityPolicyRecomposer(
                80,
                new HashSet<uint> { 80, 443 },
                smallWellKnownDestinationPortCountThreshold: 3,
                logger: logger);

            recomposer.Recompose(source);
        });

        Assert.Contains(
            "merge debug: skipped high-similarity pair because common services are small well-known destination ports.",
            logText,
            StringComparison.Ordinal);
        Assert.Contains("destinationPorts=80,443", logText, StringComparison.Ordinal);
    }

    [Fact]
    public void RecomposeHighSimilarityPolicies_WhenOnePairIsSkipped_StillProcessesOtherCandidates()
    {
        var recomposer = CreateHighSimilarityPolicyRecomposer(
            80,
            new HashSet<uint> { 80, 443 },
            smallWellKnownDestinationPortCountThreshold: 3);
        var source = new[]
        {
            CreateMergedPolicy(
                originalIndex: 800,
                originalPolicyName: "well-known-a",
                sourceAddresses: [1, 2, 3, 4, 5],
                destinationAddresses: [10, 11, 12, 13, 14],
                destinationPorts: [80, 443]),
            CreateMergedPolicy(
                originalIndex: 900,
                originalPolicyName: "well-known-b",
                sourceAddresses: [2, 3, 4, 5, 6],
                destinationAddresses: [11, 12, 13, 14, 15],
                destinationPorts: [80, 443]),
            CreateMergedPolicy(
                originalIndex: 1000,
                originalPolicyName: "normal-a",
                sourceAddresses: [101, 102, 103, 104, 105],
                destinationAddresses: [110, 111, 112, 113, 114],
                destinationPorts: [2000, 2001, 2002, 2003, 2004]),
            CreateMergedPolicy(
                originalIndex: 1100,
                originalPolicyName: "normal-b",
                sourceAddresses: [102, 103, 104, 105, 106],
                destinationAddresses: [111, 112, 113, 114, 115],
                destinationPorts: [2001, 2002, 2003, 2004, 2005])
        };

        var recomposed = recomposer.Recompose(source);

        Assert.Equal(7, recomposed.Count);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5],
            destinationAddresses: [10, 11, 12, 13, 14],
            destinationPorts: [80, 443],
            minimumIndex: 800,
            maximumIndex: 800,
            originalPolicyNames: ["well-known-a"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [2, 3, 4, 5, 6],
            destinationAddresses: [11, 12, 13, 14, 15],
            destinationPorts: [80, 443],
            minimumIndex: 900,
            maximumIndex: 900,
            originalPolicyNames: ["well-known-b"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [101, 102, 103, 104, 105, 106],
            destinationAddresses: [111, 112, 113, 114],
            destinationPorts: [2001, 2002, 2003, 2004],
            minimumIndex: 1000,
            maximumIndex: 1100,
            originalPolicyNames: ["normal-a", "normal-b"]);
    }

    [Fact]
    public void RecomposeHighSimilarityPolicies_WhenHsPercentIsRaised_DoesNotRecomposeBorderlinePair()
    {
        var recomposer = CreateHighSimilarityPolicyRecomposer(81);
        var source = new[]
        {
            CreateMergedPolicy(
                originalIndex: 1200,
                originalPolicyName: "left",
                sourceAddresses: [1, 2, 3, 4, 5],
                destinationAddresses: [10, 11, 12, 13, 14],
                destinationPorts: [20, 21, 22, 23, 24]),
            CreateMergedPolicy(
                originalIndex: 1300,
                originalPolicyName: "right",
                sourceAddresses: [5, 6, 7, 8, 9],
                destinationAddresses: [11, 12, 13, 14, 15],
                destinationPorts: [21, 22, 23, 24, 25])
        };

        var recomposed = recomposer.Recompose(source);

        Assert.Equal(2, recomposed.Count);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [1, 2, 3, 4, 5],
            destinationAddresses: [10, 11, 12, 13, 14],
            destinationPorts: [20, 21, 22, 23, 24],
            minimumIndex: 1200,
            maximumIndex: 1200,
            originalPolicyNames: ["left"]);
        AssertContainsPolicy(
            recomposed,
            sourceAddresses: [5, 6, 7, 8, 9],
            destinationAddresses: [11, 12, 13, 14, 15],
            destinationPorts: [21, 22, 23, 24, 25],
            minimumIndex: 1300,
            maximumIndex: 1300,
            originalPolicyNames: ["right"]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(101)]
    public void CreateHighSimilarityPolicyRecomposer_WhenHsPercentIsOutOfRange_Throws(uint hsPercent)
    {
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            CreateHighSimilarityPolicyRecomposer(hsPercent));

        Assert.Equal("highSimilarityThresholdPercentage", exception.ParamName);
    }

    private static HighSimilarityPolicyRecomposer CreateHighSimilarityPolicyRecomposer(
        uint highSimilarityPercentThreshold,
        IReadOnlySet<uint>? wellKnownDestinationPorts = null,
        uint? smallWellKnownDestinationPortCountThreshold = null,
        ILogger? logger = null)
    {
        return new HighSimilarityPolicyRecomposer(
            new SmallWellKnownDestinationPortMatcher(
                wellKnownDestinationPorts,
                smallWellKnownDestinationPortCountThreshold),
            highSimilarityPercentThreshold,
            logger);
    }

    private static AtomicMergeCandidate CreateAtomicPolicy(
        ulong originalIndex,
        string originalPolicyName,
        uint sourceAddressStart,
        uint sourceAddressFinish,
        uint destinationAddressStart,
        uint destinationAddressFinish,
        uint protocol,
        uint sourcePortStart,
        uint sourcePortFinish,
        uint destinationPortStart,
        uint destinationPortFinish,
        SecurityPolicyAction action = SecurityPolicyAction.Allow,
        string? kind = null,
        string application = "web-browsing",
        string groupId = "group-a")
    {
        return new AtomicMergeCandidate
        {
            FromZone = "trust",
            SourceAddress = new AddressValue
            {
                Start = sourceAddressStart,
                Finish = sourceAddressFinish
            },
            ToZone = "untrust",
            DestinationAddress = new AddressValue
            {
                Start = destinationAddressStart,
                Finish = destinationAddressFinish
            },
            Application = application,
            Service = new ServiceValue
            {
                ProtocolStart = protocol,
                ProtocolFinish = protocol,
                SourcePortStart = sourcePortStart,
                SourcePortFinish = sourcePortFinish,
                DestinationPortStart = destinationPortStart,
                DestinationPortFinish = destinationPortFinish,
                Kind = kind
            },
            Action = action,
            GroupId = groupId,
            MinimumIndex = originalIndex,
            MaximumIndex = originalIndex,
            OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { originalPolicyName }
        };
    }

    private static MergedSecurityPolicy CreateMergedPolicy(
        ulong originalIndex,
        string originalPolicyName,
        IReadOnlyCollection<uint> sourceAddresses,
        IReadOnlyCollection<uint> destinationAddresses,
        IReadOnlyCollection<uint> destinationPorts)
    {
        return new MergedSecurityPolicy
        {
            FromZones = new HashSet<string>(StringComparer.Ordinal) { "trust" },
            SourceAddresses = sourceAddresses.Select(CreateAddressValue).ToHashSet(),
            ToZones = new HashSet<string>(StringComparer.Ordinal) { "untrust" },
            DestinationAddresses = destinationAddresses.Select(CreateAddressValue).ToHashSet(),
            Applications = new HashSet<string>(StringComparer.Ordinal) { "web-browsing" },
            Services = destinationPorts.Select(CreateServiceValue).ToHashSet(),
            Action = SecurityPolicyAction.Allow,
            GroupId = "group-a",
            MinimumIndex = originalIndex,
            MaximumIndex = originalIndex,
            OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { originalPolicyName }
        };
    }

    private static AddressValue CreateAddressValue(uint value)
    {
        return new AddressValue
        {
            Start = value,
            Finish = value
        };
    }

    private static ServiceValue CreateServiceValue(uint destinationPort)
    {
        return new ServiceValue
        {
            ProtocolStart = 6,
            ProtocolFinish = 6,
            SourcePortStart = 1,
            SourcePortFinish = 65535,
            DestinationPortStart = destinationPort,
            DestinationPortFinish = destinationPort,
            Kind = "service"
        };
    }

    private static string CaptureDebugLog(Action<ILogger> action)
    {
        var logPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.log");

        try
        {
            ProgramLogger.Dispose();
            var logger = ProgramLogger.GetLogger(LogType.File, logPath, LogLevel.Debug);

            action(logger);

            ProgramLogger.Dispose();
            return File.Exists(logPath)
                ? ReadAllTextShared(logPath)
                : string.Empty;
        }
        finally
        {
            ProgramLogger.Dispose();

            if (File.Exists(logPath))
            {
                try
                {
                    File.Delete(logPath);
                }
                catch (IOException)
                {
                    // 共有ロガー破棄直後は一時的にハンドルが残ることがあるため、後始末はベストエフォートとする。
                }
            }
        }
    }

    private static string ReadAllTextShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static void AssertContainsPolicy(
        IEnumerable<MergedSecurityPolicy> policies,
        IReadOnlyCollection<uint> sourceAddresses,
        IReadOnlyCollection<uint> destinationAddresses,
        IReadOnlyCollection<uint> destinationPorts,
        ulong minimumIndex,
        ulong maximumIndex,
        IReadOnlyCollection<string> originalPolicyNames)
    {
        var expectedSourceAddresses = sourceAddresses.OrderBy(static value => value).ToArray();
        var expectedDestinationAddresses = destinationAddresses.OrderBy(static value => value).ToArray();
        var expectedDestinationPorts = destinationPorts.OrderBy(static value => value).ToArray();
        var expectedOriginalPolicyNames = originalPolicyNames.OrderBy(static value => value).ToArray();

        var matched = policies.Where(
            policy => policy.MinimumIndex == minimumIndex
                && policy.MaximumIndex == maximumIndex
                && policy.SourceAddresses.Select(address => address.Start).OrderBy(static value => value).SequenceEqual(expectedSourceAddresses)
                && policy.DestinationAddresses.Select(address => address.Start).OrderBy(static value => value).SequenceEqual(expectedDestinationAddresses)
                && policy.Services.Select(service => service.DestinationPortStart).OrderBy(static value => value).SequenceEqual(expectedDestinationPorts)
                && policy.OriginalPolicyNames.OrderBy(static value => value).SequenceEqual(expectedOriginalPolicyNames));

        Assert.Single(matched);
    }
}
