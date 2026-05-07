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
                CreatePolicy(1, sourceAddressValues: ["10.0.0.1/32", "10.0.0.2/32"]),
                CreatePolicy(2, sourceAddressValue: "10.0.0.3/32")
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

    [Theory]
    [InlineData("CN", "CN")]
    [InlineData("192.168.1.10/24", "network address")]
    [InlineData("192.168.1.10", "/32")]
    public void Run_WhenAddressCannotBeExpanded_SkipsPolicyAndReportsSkippedPolicy(
        string sourceAddressValue,
        string expectedReason)
    {
        var runner = new SecurityPolicyAtomizeRunner(CreateResolver(), threshold: 10);
        var appendedBatches = new List<AtomicSecurityPolicy[]>();
        var skippedPolicies = new List<SecurityPolicyAtomizeRunner.SkippedPolicy>();

        var result = runner.Run(
            [
                CreatePolicy(1),
                CreatePolicy(2, sourceAddressValue: sourceAddressValue)
            ],
            policies => appendedBatches.Add(policies.ToArray()),
            reportSkippedPolicy: skippedPolicies.Add);

        Assert.Equal(2, result.ProcessedSourcePolicyCount);
        Assert.Equal(1, result.SkippedSourcePolicyCount);

        var batch = Assert.Single(appendedBatches);
        var atomicPolicy = Assert.Single(batch);
        Assert.Equal("policy-1", atomicPolicy.OriginalPolicyName);

        var skippedPolicy = Assert.Single(skippedPolicies);
        Assert.Equal("policy-2", skippedPolicy.PolicyName);
        Assert.Equal(2u, skippedPolicy.PolicyIndex);
        Assert.Contains(expectedReason, skippedPolicy.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Run_WhenAddressGroupResolvesToNonIpv4Token_SkipsPolicy()
    {
        var runner = new SecurityPolicyAtomizeRunner(
            CreateResolver(
                new FixedAddressDefinitionLookup(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["country-cn"] = "CN"
                }),
                new FixedAddressGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    ["geo-cn"] = ["country-cn"]
                })),
            threshold: 10);
        var appendedBatches = new List<AtomicSecurityPolicy[]>();
        var skippedPolicies = new List<SecurityPolicyAtomizeRunner.SkippedPolicy>();

        var result = runner.Run(
            [CreatePolicy(1, sourceAddressValue: "geo-cn")],
            policies => appendedBatches.Add(policies.ToArray()),
            reportSkippedPolicy: skippedPolicies.Add);

        Assert.Equal(1, result.ProcessedSourcePolicyCount);
        Assert.Equal(1, result.SkippedSourcePolicyCount);
        Assert.Empty(appendedBatches);

        var skippedPolicy = Assert.Single(skippedPolicies);
        Assert.Equal("policy-1", skippedPolicy.PolicyName);
        Assert.Contains("CN", skippedPolicy.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Run_WhenAddressGroupRecursionOccurs_ThrowsInvalidOperationException()
    {
        var runner = new SecurityPolicyAtomizeRunner(
            CreateResolver(
                new EmptyAddressDefinitionLookup(),
                new FixedAddressGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    ["loop"] = ["loop"]
                })),
            threshold: 10);

        Assert.Throws<InvalidOperationException>(() => runner.Run(
            [CreatePolicy(1, sourceAddressValue: "loop")],
            static _ => { }));
    }

    [Fact]
    public void Run_WhenSourcePolicyProcessed_ReportsProcessedCountForEachSourcePolicy()
    {
        var runner = new SecurityPolicyAtomizeRunner(CreateResolver(), threshold: 10);
        var reportedCounts = new List<int>();

        var result = runner.Run(
            [
                CreatePolicy(1),
                CreatePolicy(2),
                CreatePolicy(3)
            ],
            static _ => { },
            onSourcePolicyProcessed: reportedCounts.Add);

        Assert.Equal(3, result.ProcessedSourcePolicyCount);
        Assert.Equal(0, result.SkippedSourcePolicyCount);
        Assert.Equal([1, 2, 3], reportedCounts);
    }

    [Fact]
    public void Run_WhenInvalidThreePartServiceReferenceReachesDomain_FallsBackToKind()
    {
        var serviceFallbacks = new List<SecurityPolicyAtomizeRunner.ServiceReferenceKindFallback>();
        var serviceResolver = new ServiceReferenceResolver(
            new FixedServiceDefinitionLookup(),
            new EmptyServiceGroupLookup());
        var policyResolver = CreateResolver(serviceResolver: serviceResolver);
        var runner = new SecurityPolicyAtomizeRunner(
            policyResolver,
            threshold: 10);
        var appendedBatches = new List<AtomicSecurityPolicy[]>();

        runner.Run(
            [CreatePolicy(1, serviceReferences: ["tcp 0-0 80"])],
            policies => appendedBatches.Add(policies.ToArray()),
            reportServiceReferenceKindFallback: serviceFallbacks.Add);

        var atomicPolicy = Assert.Single(Assert.Single(appendedBatches));
        Assert.Equal("tcp 0-0 80", atomicPolicy.Service.Kind);
        Assert.Equal(255U, atomicPolicy.Service.ProtocolStart);
        Assert.Equal(0U, atomicPolicy.Service.SourcePortStart);
        Assert.Equal(0U, atomicPolicy.Service.DestinationPortStart);

        var serviceFallback = Assert.Single(serviceFallbacks);
        Assert.Equal("policy-1", serviceFallback.PolicyName);
        Assert.Equal(1u, serviceFallback.PolicyIndex);
        Assert.Equal("tcp 0-0 80", serviceFallback.ServiceReference);
    }

    private static ImportedSecurityPolicy CreatePolicy(
        int index,
        SecurityPolicyAction action = SecurityPolicyAction.Allow,
        string sourceAddressValue = "10.0.0.1/32",
        IReadOnlyList<string>? sourceAddressValues = null,
        IReadOnlyList<string>? serviceReferences = null)
    {
        return new ImportedSecurityPolicy
        {
            Name = $"policy-{index}",
            Index = (uint)index,
            FromZones = ["trust"],
            SourceAddressReferences = (sourceAddressValues ?? [sourceAddressValue]).ToArray(),
            ToZones = ["untrust"],
            DestinationAddressReferences = ["10.0.0.2/32"],
            Applications = ["any"],
            ServiceReferences = serviceReferences?.ToArray() ?? ["service-http"],
            Action = action,
            GroupId = $"group-{index}"
        };
    }

    private static SecurityPolicyResolver CreateResolver(
        ILookupRepository<string>? addressDefinitionLookup = null,
        ILookupRepository<IReadOnlyList<string>>? addressGroupLookup = null,
        ServiceReferenceResolver? serviceResolver = null)
    {
        return new SecurityPolicyResolver(
            new AddressReferenceResolver(
                addressDefinitionLookup ?? new EmptyAddressDefinitionLookup(),
                addressGroupLookup ?? new EmptyAddressGroupLookup()),
            serviceResolver ?? new ServiceReferenceResolver(
                new FixedServiceDefinitionLookup(),
                new EmptyServiceGroupLookup()));
    }

    private sealed class EmptyAddressDefinitionLookup : ILookupRepository<string>
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

    private sealed class FixedAddressDefinitionLookup : ILookupRepository<string>
    {
        private readonly IReadOnlyDictionary<string, string> values;

        public FixedAddressDefinitionLookup(IReadOnlyDictionary<string, string> values)
        {
            this.values = values;
        }

        public bool TryGetByName(string name, out string value)
        {
            return values.TryGetValue(name, out value!);
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class FixedAddressGroupLookup : ILookupRepository<IReadOnlyList<string>>
    {
        private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> values;

        public FixedAddressGroupLookup(IReadOnlyDictionary<string, IReadOnlyList<string>> values)
        {
            this.values = values;
        }

        public bool TryGetByName(string name, out IReadOnlyList<string> value)
        {
            return values.TryGetValue(name, out value!);
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class FixedServiceDefinitionLookup : ILookupRepository<ServiceDefinition>
    {
        public bool TryGetByName(string name, out ServiceDefinition serviceDefinition)
        {
            if (name.Equals("service-http", StringComparison.Ordinal))
            {
                serviceDefinition = new ServiceDefinition
                {
                    Name = "service-http",
                    Protocol = "6",
                    SourcePort = "1-65535",
                    DestinationPort = "80",
                    Kind = null
                };
                return true;
            }

            serviceDefinition = null!;
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
