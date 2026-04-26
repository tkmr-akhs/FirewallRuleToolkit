using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class AddressReferenceResolverTests
{
    [Fact]
    public void Resolve_ObjectAndGroup_ExpandsNormalizedStoreValues()
    {
        var resolver = new AddressReferenceResolver(
            new StubAddressDefinitionStore(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["web"] = "192.168.0.10/32",
                ["range"] = "192.168.0.20-192.168.0.21"
            }),
            new StubAddressGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["servers"] = ["web", "range"]
            }));

        var resolved = resolver.Resolve(["servers", "10.0.0.0/24"]).ToArray();

        Assert.Equal(["192.168.0.10/32", "192.168.0.20-192.168.0.21", "10.0.0.0/24"], resolved.Select(item => item.Value));
    }

    [Fact]
    public void Resolve_InlineHostAddress_NormalizesToSlash32()
    {
        var resolver = new AddressReferenceResolver(
            new StubAddressDefinitionStore(new Dictionary<string, string>(StringComparer.Ordinal)),
            new StubAddressGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["192.168.0.10"]).Single();

        Assert.Equal("192.168.0.10/32", resolved.Value);
    }

    [Fact]
    public void Resolve_AnyAddress_UsesLowercaseBuiltInName()
    {
        var resolver = new AddressReferenceResolver(
            new StubAddressDefinitionStore(new Dictionary<string, string>(StringComparer.Ordinal)),
            new StubAddressGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["any"]).Single();

        Assert.Equal("0.0.0.0/0", resolved.Value);
    }

    [Fact]
    public void Resolve_AnyAddress_WhenCaseDiffers_DoesNotUseBuiltInName()
    {
        var resolver = new AddressReferenceResolver(
            new StubAddressDefinitionStore(new Dictionary<string, string>(StringComparer.Ordinal)),
            new StubAddressGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)));

        var resolved = resolver.Resolve(["ANY"]).Single();

        Assert.Equal("ANY", resolved.Value);
    }

    [Fact]
    public void Resolve_ObjectAndGroupNames_AreCaseSensitive()
    {
        var resolver = new AddressReferenceResolver(
            new StubAddressDefinitionStore(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Web"] = "192.168.0.10/32"
            }),
            new StubAddressGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["Servers"] = ["Web"]
            }));

        var resolved = resolver.Resolve(["web", "servers"]).ToArray();

        Assert.Equal(["web", "servers"], resolved.Select(static item => item.Value));
    }

    [Fact]
    public void Resolve_RecursiveGroup_ThrowsInvalidOperationException()
    {
        var resolver = new AddressReferenceResolver(
            new StubAddressDefinitionStore(new Dictionary<string, string>(StringComparer.Ordinal)),
            new StubAddressGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["loop"] = ["loop"]
            }));

        Assert.Throws<InvalidOperationException>(() => resolver.Resolve(["loop"]).ToArray());
    }

    [Fact]
    public void Resolve_GroupNamesDifferingOnlyByCase_DoesNotTreatAsRecursion()
    {
        var resolver = new AddressReferenceResolver(
            new StubAddressDefinitionStore(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["host"] = "192.168.0.10/32"
            }),
            new StubAddressGroupStore(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["Loop"] = ["loop"],
                ["loop"] = ["host"]
            }));

        var resolved = resolver.Resolve(["Loop"]).Single();

        Assert.Equal("192.168.0.10/32", resolved.Value);
    }

    private sealed class StubAddressDefinitionStore : ILookupRepository<string>
    {
        private readonly IReadOnlyDictionary<string, string> values;

        public StubAddressDefinitionStore(IReadOnlyDictionary<string, string> values)
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

    private sealed class StubAddressGroupStore : ILookupRepository<IReadOnlyList<string>>
    {
        private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> groups;

        public StubAddressGroupStore(IReadOnlyDictionary<string, IReadOnlyList<string>> groups)
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
