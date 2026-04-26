using FirewallRuleToolkit.Domain;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class ServiceReferenceResolverTests
{
    [Fact]
    public void Resolve_ObjectAndGroup_ExpandsNormalizedStoreValues()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["svc-web"] = new()
                {
                    Name = "svc-web",
                    Protocol = "6",
                    SourcePort = "1-65535",
                    DestinationPort = "443",
                    Kind = null
                },
                ["svc-app-default"] = new()
                {
                    Name = "svc-app-default",
                    Protocol = "255",
                    SourcePort = "0",
                    DestinationPort = "0",
                    Kind = "application-default"
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["bundle"] = ["svc-web", "udp 1-65535 53", "svc-app-default"]
            }));

        var resolved = resolver.Resolve(["bundle"]).ToArray();

        Assert.Collection(
            resolved,
            item =>
            {
                Assert.Equal("6", item.Protocol);
                Assert.Equal("1-65535", item.SourcePort);
                Assert.Equal("443", item.DestinationPort);
                Assert.Null(item.Kind);
            },
            item =>
            {
                Assert.Equal("17", item.Protocol);
                Assert.Equal("1-65535", item.SourcePort);
                Assert.Equal("53", item.DestinationPort);
                Assert.Null(item.Kind);
            },
            item =>
            {
                Assert.Equal("255", item.Protocol);
                Assert.Equal("0", item.SourcePort);
                Assert.Equal("0", item.DestinationPort);
                Assert.Equal("application-default", item.Kind);
            });
    }

    [Fact]
    public void Resolve_DirectService_WithExplicitSourceAndDestinationPorts_NormalizesValues()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["tcp any 80-90"]).Single();

        Assert.Equal("6", resolved.Protocol);
        Assert.Equal("1-65535", resolved.SourcePort);
        Assert.Equal("80-90", resolved.DestinationPort);
        Assert.Null(resolved.Kind);
        Assert.NotEmpty(ResolvedServiceExpander.Parse(resolved));
    }

    [Fact]
    public void Resolve_DirectService_WhenSourcePortIsOmitted_FallsBackToKind()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["tcp 80"]).Single();

        Assert.Equal("255", resolved.Protocol);
        Assert.Equal("0", resolved.SourcePort);
        Assert.Equal("0", resolved.DestinationPort);
        Assert.Equal("tcp 80", resolved.Kind);
    }

    [Fact]
    public void Resolve_DirectService_WhenThreePartValueIsInvalid_FallsBackToKind()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["tcp hoge 80"]).Single();

        Assert.Equal("255", resolved.Protocol);
        Assert.Equal("0", resolved.SourcePort);
        Assert.Equal("0", resolved.DestinationPort);
        Assert.Equal("tcp hoge 80", resolved.Kind);
    }

    [Fact]
    public void Resolve_DirectService_WhenAnyCaseDiffers_FallsBackToKind()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["tcp ANY 80"]).Single();

        Assert.Equal("255", resolved.Protocol);
        Assert.Equal("0", resolved.SourcePort);
        Assert.Equal("0", resolved.DestinationPort);
        Assert.Equal("tcp ANY 80", resolved.Kind);
    }

    [Fact]
    public void Resolve_DirectService_WhenProtocolAliasCaseDiffers_FallsBackToKind()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["TCP any 80"]).Single();

        Assert.Equal("255", resolved.Protocol);
        Assert.Equal("0", resolved.SourcePort);
        Assert.Equal("0", resolved.DestinationPort);
        Assert.Equal("TCP any 80", resolved.Kind);
    }

    [Fact]
    public void Resolve_AnyService_UsesLowercaseBuiltInName()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["any"]).Single();

        Assert.Equal("0-255", resolved.Protocol);
        Assert.Equal("0-65535", resolved.SourcePort);
        Assert.Equal("0-65535", resolved.DestinationPort);
        Assert.Null(resolved.Kind);
    }

    [Fact]
    public void Resolve_AnyService_WhenCaseDiffers_DoesNotUseBuiltInName()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["ANY"]).Single();

        Assert.Equal("255", resolved.Protocol);
        Assert.Equal("0", resolved.SourcePort);
        Assert.Equal("0", resolved.DestinationPort);
        Assert.Equal("ANY", resolved.Kind);
    }

    [Fact]
    public void Resolve_AnyService_WhenServiceDefinitionNamedAnyExists_UsesBuiltInAny()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["any"] = new()
                {
                    Name = "any",
                    Protocol = "6",
                    SourcePort = "1-65535",
                    DestinationPort = "443",
                    Kind = null
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["any"]).Single();

        Assert.Equal("0-255", resolved.Protocol);
        Assert.Equal("0-65535", resolved.SourcePort);
        Assert.Equal("0-65535", resolved.DestinationPort);
        Assert.Null(resolved.Kind);
    }

    [Fact]
    public void Resolve_AnyService_WhenServiceGroupNamedAnyExists_UsesBuiltInAny()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["svc-web"] = new()
                {
                    Name = "svc-web",
                    Protocol = "6",
                    SourcePort = "1-65535",
                    DestinationPort = "443",
                    Kind = null
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["any"] = ["svc-web"]
            }));

        var resolved = resolver.Resolve(["any"]).Single();

        Assert.Equal("0-255", resolved.Protocol);
        Assert.Equal("0-65535", resolved.SourcePort);
        Assert.Equal("0-65535", resolved.DestinationPort);
        Assert.Null(resolved.Kind);
    }

    [Fact]
    public void Resolve_ServiceDefinition_WithAnyValues_NormalizesForExpansion()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["svc-any"] = new()
                {
                    Name = "svc-any",
                    Protocol = "any",
                    SourcePort = "any",
                    DestinationPort = "any",
                    Kind = null
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["svc-any"]).Single();

        Assert.Equal("0-254", resolved.Protocol);
        Assert.Equal("1-65535", resolved.SourcePort);
        Assert.Equal("1-65535", resolved.DestinationPort);
        Assert.NotEmpty(ResolvedServiceExpander.Parse(resolved));
    }

    [Fact]
    public void Resolve_ServiceDefinition_WithProtocolRangesEnding255_NormalizesRangeEndTo254()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["svc-protocol-any"] = new()
                {
                    Name = "svc-protocol-any",
                    Protocol = "0-255,100-255,6",
                    SourcePort = "any",
                    DestinationPort = "any",
                    Kind = null
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["svc-protocol-any"]).Single();

        Assert.Equal("0-254,100-254,6", resolved.Protocol);
        Assert.Equal("1-65535", resolved.SourcePort);
        Assert.Equal("1-65535", resolved.DestinationPort);
        Assert.NotEmpty(ResolvedServiceExpander.Parse(resolved));
    }

    [Fact]
    public void Resolve_ServiceDefinition_WithDelimitedPortRangesStarting0_NormalizesEachRangeStartTo1()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["svc-port-any"] = new()
                {
                    Name = "svc-port-any",
                    Protocol = "6",
                    SourcePort = "80,0-65535,254",
                    DestinationPort = "0-1023,443",
                    Kind = null
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["svc-port-any"]).Single();

        Assert.Equal("6", resolved.Protocol);
        Assert.Equal("80,1-65535,254", resolved.SourcePort);
        Assert.Equal("1-1023,443", resolved.DestinationPort);
        Assert.NotEmpty(ResolvedServiceExpander.Parse(resolved));
    }

    [Fact]
    public void Resolve_ServiceDefinition_UsesNormalizedStoreValuesAsIs()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["svc-range"] = new()
                {
                    Name = "svc-range",
                    Protocol = "6",
                    SourcePort = "1-65535",
                    DestinationPort = "1-65535",
                    Kind = null
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["svc-range"]).Single();

        Assert.Equal("6", resolved.Protocol);
        Assert.Equal("1-65535", resolved.SourcePort);
        Assert.Equal("1-65535", resolved.DestinationPort);
        Assert.Null(resolved.Kind);
    }

    [Fact]
    public void Resolve_ServiceDefinition_WithCompositePortExpression_PreservesText()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["svc-composite"] = new()
                {
                    Name = "svc-composite",
                    Protocol = "6",
                    SourcePort = "1,3,5-7,8",
                    DestinationPort = "80,443,1000-1002",
                    Kind = null
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["svc-composite"]).Single();

        Assert.Equal("6", resolved.Protocol);
        Assert.Equal("1,3,5-7,8", resolved.SourcePort);
        Assert.Equal("80,443,1000-1002", resolved.DestinationPort);
        Assert.Null(resolved.Kind);
    }

    [Fact]
    public void Resolve_ObjectAndGroupNames_AreCaseSensitive()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["SvcWeb"] = new()
                {
                    Name = "SvcWeb",
                    Protocol = "6",
                    SourcePort = "1-65535",
                    DestinationPort = "443",
                    Kind = null
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["Bundle"] = ["SvcWeb"]
            }));

        var resolved = resolver.Resolve(["svcweb", "bundle"]).ToArray();

        Assert.Equal(["svcweb", "bundle"], resolved.Select(static item => item.Kind));
        Assert.All(resolved, static item =>
        {
            Assert.Equal("255", item.Protocol);
            Assert.Equal("0", item.SourcePort);
            Assert.Equal("0", item.DestinationPort);
        });
    }

    [Fact]
    public void Resolve_RecursiveGroup_ThrowsInvalidOperationException()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["loop"] = ["loop"]
            }));

        Assert.Throws<InvalidOperationException>(() => resolver.Resolve(["loop"]).ToArray());
    }

    [Fact]
    public void Resolve_GroupNamesDifferingOnlyByCase_DoesNotTreatAsRecursion()
    {
        var resolver = new ServiceReferenceResolver(
            new StubServiceDefinitionStore(new Dictionary<string, ServiceDefinition>(StringComparer.Ordinal)
            {
                ["svc-web"] = new()
                {
                    Name = "svc-web",
                    Protocol = "6",
                    SourcePort = "1-65535",
                    DestinationPort = "443",
                    Kind = null
                }
            }),
            new StubServiceGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["Loop"] = ["loop"],
                ["loop"] = ["svc-web"]
            }));

        var resolved = resolver.Resolve(["Loop"]).Single();

        Assert.Equal("6", resolved.Protocol);
        Assert.Equal("1-65535", resolved.SourcePort);
        Assert.Equal("443", resolved.DestinationPort);
        Assert.Null(resolved.Kind);
    }

    private sealed class StubServiceDefinitionStore : ILookupRepository<ServiceDefinition>
    {
        private readonly IReadOnlyDictionary<string, ServiceDefinition> values;

        public StubServiceDefinitionStore(IReadOnlyDictionary<string, ServiceDefinition> values)
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

    private sealed class StubServiceGroupStore : ILookupRepository<IReadOnlyList<string>>
    {
        private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> groups;

        public StubServiceGroupStore(IReadOnlyDictionary<string, IReadOnlyList<string>> groups)
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
