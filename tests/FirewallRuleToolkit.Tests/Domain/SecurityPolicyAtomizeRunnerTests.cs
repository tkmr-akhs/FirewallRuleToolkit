using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class SecurityPolicyAtomizeRunnerTests
{
    [Fact]
    public void Run_AppendsAtomizedPoliciesPerSourcePolicy()
    {
        var runner = new SecurityPolicyAtomizeRunner(CreateResolver(), threshold: 10);
        var appendedBatches = new List<AtomicSecurityPolicy[]>();

        var result = runner.Run(
            [
                CreatePolicy(1, sourceAddressValues: ["10.0.0.1", "10.0.0.2"]),
                CreatePolicy(2, sourceAddressValue: "10.0.0.3")
            ],
            policies => appendedBatches.Add(policies.ToArray()));

        Assert.Equal(2, result.ProcessedSourcePolicyCount);
        Assert.Equal(0, result.SkippedSourcePolicyCount);
        Assert.Collection(
            appendedBatches,
            batch =>
            {
                Assert.Equal(2, batch.Length);
                Assert.All(batch, static policy => Assert.Equal("policy-1", policy.OriginalPolicyName));
            },
            batch =>
            {
                var policy = Assert.Single(batch);
                Assert.Equal("policy-2", policy.OriginalPolicyName);
            });
    }

    [Fact]
    public void Run_WhenSkippedPolicyOccurs_ReturnsProcessedAndSkippedCounts()
    {
        var runner = new SecurityPolicyAtomizeRunner(CreateResolver(), threshold: 10);
        var skippedPolicies = new List<SecurityPolicyAtomizeRunner.SkippedPolicy>();

        var result = runner.Run(
            [
                CreatePolicy(1),
                CreatePolicy(2, sourceAddressValue: "invalid")
            ],
            static _ => { },
            reportSkippedPolicy: skippedPolicies.Add);

        Assert.Equal(2, result.ProcessedSourcePolicyCount);
        Assert.Equal(1, result.SkippedSourcePolicyCount);

        var skipped = Assert.Single(skippedPolicies);
        Assert.Equal("policy-2", skipped.PolicyName);
        Assert.Equal((uint)2, skipped.PolicyIndex);
        Assert.Equal("Unsupported IPv4 address: invalid", skipped.Reason);
    }

    private static ImportedSecurityPolicy CreatePolicy(
        int index,
        SecurityPolicyAction action = SecurityPolicyAction.Allow,
        string sourceAddressValue = "10.0.0.1",
        IReadOnlyList<string>? sourceAddressValues = null)
    {
        return new ImportedSecurityPolicy
        {
            Name = $"policy-{index}",
            Index = (uint)index,
            FromZones = ["trust"],
            SourceAddressReferences = (sourceAddressValues ?? [sourceAddressValue]).ToArray(),
            ToZones = ["untrust"],
            DestinationAddressReferences = ["10.0.0.2"],
            Applications = ["any"],
            ServiceReferences = ["service-http"],
            Action = action,
            GroupId = $"group-{index}"
        };
    }

    private static SecurityPolicyResolver CreateResolver()
    {
        return new SecurityPolicyResolver(
            new AddressReferenceResolver(
                new EmptyAddressObjectLookup(),
                new EmptyAddressGroupLookup()),
            new ServiceReferenceResolver(
                new FixedServiceObjectLookup(),
                new EmptyServiceGroupLookup()));
    }

    private sealed class EmptyAddressObjectLookup : ILookupRepository<string>
    {
        public bool TryGetByName(string name, out string value)
        {
            value = string.Empty;
            return false;
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class EmptyAddressGroupLookup : ILookupRepository<IReadOnlyList<string>>
    {
        public bool TryGetByName(string groupName, out IReadOnlyList<string> members)
        {
            members = [];
            return false;
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class FixedServiceObjectLookup : ILookupRepository<ServiceObject>
    {
        public bool TryGetByName(string name, out ServiceObject serviceObject)
        {
            if (name.Equals("service-http", StringComparison.Ordinal))
            {
                serviceObject = new ServiceObject
                {
                    Name = "service-http",
                    Protocol = "6",
                    SourcePort = "0-65535",
                    DestinationPort = "80",
                    Kind = "service"
                };
                return true;
            }

            serviceObject = null!;
            return false;
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class EmptyServiceGroupLookup : ILookupRepository<IReadOnlyList<string>>
    {
        public bool TryGetByName(string groupName, out IReadOnlyList<string> members)
        {
            members = [];
            return false;
        }

        public void EnsureAvailable()
        {
        }
    }
}
