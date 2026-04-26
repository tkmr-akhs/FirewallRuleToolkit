using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class SecurityPolicyResolverTests
{
    [Fact]
    public void Resolve_WhenPolicyContainsObjectAndGroupReferences_ExpandsToResolvedValues()
    {
        var resolver = new SecurityPolicyResolver(
            new AddressReferenceResolver(
                new StubAddressDefinitionLookup(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["src-host"] = "192.168.0.10/32",
                    ["dst-host"] = "10.0.0.10/32"
                }),
                new StubAddressGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    ["src-group"] = ["src-host"]
                })),
            new ServiceReferenceResolver(
                new StubServiceDefinitionLookup(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
                {
                    ["svc-https"] = new ServiceDefinition
                    {
                        Name = "svc-https",
                        Protocol = "6",
                        SourcePort = "1-65535",
                        DestinationPort = "443",
                        Kind = null
                    }
                }),
                new StubServiceGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    ["svc-group"] = ["svc-https", "application-default"]
                })));

        var resolved = resolver.Resolve(
            new ImportedSecurityPolicy
            {
                Index = 1,
                Name = "allow-web",
                FromZones = ["trust"],
                SourceAddressReferences = ["src-group", "192.168.1.1"],
                ToZones = ["untrust"],
                DestinationAddressReferences = ["dst-host"],
                Applications = ["web-browsing"],
                ServiceReferences = ["svc-group"],
                Action = SecurityPolicyAction.Allow,
                GroupId = "group-a"
            });

        Assert.Equal(["192.168.0.10/32", "192.168.1.1/32"], resolved.SourceAddresses.Select(static x => x.Value));
        Assert.Equal(["10.0.0.10/32"], resolved.DestinationAddresses.Select(static x => x.Value));

        Assert.Collection(
            resolved.Services,
            service =>
            {
                Assert.Equal("6", service.Protocol);
                Assert.Equal("1-65535", service.SourcePort);
                Assert.Equal("443", service.DestinationPort);
                Assert.Null(service.Kind);
            },
            service =>
            {
                Assert.Equal("255", service.Protocol);
                Assert.Equal("0", service.SourcePort);
                Assert.Equal("0", service.DestinationPort);
                Assert.Equal("application-default", service.Kind);
            });
    }

    private sealed class StubAddressDefinitionLookup : ILookupRepository<string>
    {
        private readonly IReadOnlyDictionary<string, string> values;

        public StubAddressDefinitionLookup(IReadOnlyDictionary<string, string> values)
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

    private sealed class StubAddressGroupLookup : ILookupRepository<IReadOnlyList<string>>
    {
        private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> groups;

        public StubAddressGroupLookup(IReadOnlyDictionary<string, IReadOnlyList<string>> groups)
        {
            this.groups = groups;
        }

        public bool TryGetByName(string groupName, out IReadOnlyList<string> members)
        {
            return groups.TryGetValue(groupName, out members!);
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class StubServiceDefinitionLookup : ILookupRepository<ServiceDefinition>
    {
        private readonly IReadOnlyDictionary<string, ServiceDefinition> values;

        public StubServiceDefinitionLookup(IReadOnlyDictionary<string, ServiceDefinition> values)
        {
            this.values = values;
        }

        public bool TryGetByName(string name, out ServiceDefinition serviceDefinition)
        {
            return values.TryGetValue(name, out serviceDefinition!);
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class StubServiceGroupLookup : ILookupRepository<IReadOnlyList<string>>
    {
        private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> groups;

        public StubServiceGroupLookup(IReadOnlyDictionary<string, IReadOnlyList<string>> groups)
        {
            this.groups = groups;
        }

        public bool TryGetByName(string groupName, out IReadOnlyList<string> members)
        {
            return groups.TryGetValue(groupName, out members!);
        }

        public void EnsureAvailable()
        {
        }
    }
}
