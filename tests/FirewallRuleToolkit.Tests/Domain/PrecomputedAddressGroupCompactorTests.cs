using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.Services;
using FirewallRuleToolkit.Domain.ValueObjects;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class AddressGroupCompactorTests
{
    [Fact]
    public void Compact_WhenGroupMembersAreIncluded_ReplacesThemWithGroupName()
    {
        var compactor = new AddressGroupCompactor(
            new StubAddressGroupRepository(
            [
                new AddressGroupMembership { GroupName = "branch-offices", MemberName = "host-a" },
                new AddressGroupMembership { GroupName = "branch-offices", MemberName = "host-b" },
                new AddressGroupMembership { GroupName = "ignored-single", MemberName = "host-c" }
            ]),
            new StubAddressDefinitionLookup(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["host-a"] = "192.168.1.10/32",
                ["host-b"] = "192.168.1.11/32",
                ["host-c"] = "192.168.1.12/32"
            }),
            new StubAddressGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["branch-offices"] = ["host-a", "host-b"],
                ["ignored-single"] = ["host-c"]
            }),
            rangeSplitThreshold: 10);

        var result = compactor.Compact(
        [
            new AddressValue { Start = 0xC0A8010A, Finish = 0xC0A8010A },
            new AddressValue { Start = 0xC0A8010B, Finish = 0xC0A8010B },
            new AddressValue { Start = 0xC0A80163, Finish = 0xC0A80163 }
        ]);

        Assert.Equal(["branch-offices"], result.GroupNames);
        Assert.Equal(
            [new AddressValue { Start = 0xC0A80163, Finish = 0xC0A80163 }],
            result.RemainingAddresses);
    }

    [Fact]
    public void Compact_WhenNestedGroupCoversMoreAddresses_PrefersLargerGroup()
    {
        var compactor = new AddressGroupCompactor(
            new StubAddressGroupRepository(
            [
                new AddressGroupMembership { GroupName = "pair", MemberName = "host-a" },
                new AddressGroupMembership { GroupName = "pair", MemberName = "host-b" },
                new AddressGroupMembership { GroupName = "pair-plus", MemberName = "pair" },
                new AddressGroupMembership { GroupName = "pair-plus", MemberName = "host-c" }
            ]),
            new StubAddressDefinitionLookup(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["host-a"] = "10.0.0.1/32",
                ["host-b"] = "10.0.0.2/32",
                ["host-c"] = "10.0.0.3/32"
            }),
            new StubAddressGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["pair"] = ["host-a", "host-b"],
                ["pair-plus"] = ["pair", "host-c"]
            }),
            rangeSplitThreshold: 10);

        var result = compactor.Compact(
        [
            new AddressValue { Start = 0x0A000001, Finish = 0x0A000001 },
            new AddressValue { Start = 0x0A000002, Finish = 0x0A000002 },
            new AddressValue { Start = 0x0A000003, Finish = 0x0A000003 }
        ]);

        Assert.Equal(["pair-plus"], result.GroupNames);
        Assert.Empty(result.RemainingAddresses);
    }

    [Fact]
    public void Compact_WhenGroupMemberIsShortHyphenRange_SplitsByThresholdAndCompacts()
    {
        var compactor = new AddressGroupCompactor(
            new StubAddressGroupRepository(
            [
                new AddressGroupMembership { GroupName = "small-range", MemberName = "range-a" }
            ]),
            new StubAddressDefinitionLookup(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["range-a"] = "10.0.0.1-10.0.0.3"
            }),
            new StubAddressGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["small-range"] = ["range-a"]
            }),
            rangeSplitThreshold: 10);

        var result = compactor.Compact(
        [
            new AddressValue { Start = 0x0A000001, Finish = 0x0A000001 },
            new AddressValue { Start = 0x0A000002, Finish = 0x0A000002 },
            new AddressValue { Start = 0x0A000003, Finish = 0x0A000003 }
        ]);

        Assert.Equal(["small-range"], result.GroupNames);
        Assert.Empty(result.RemainingAddresses);
    }

    [Fact]
    public void Compact_WhenGroupNamesDifferOnlyByCase_TreatsThemAsSeparateCandidates()
    {
        var compactor = new AddressGroupCompactor(
            new StubAddressGroupRepository(
            [
                new AddressGroupMembership { GroupName = "Group", MemberName = "host-a" },
                new AddressGroupMembership { GroupName = "Group", MemberName = "host-b" },
                new AddressGroupMembership { GroupName = "group", MemberName = "host-c" },
                new AddressGroupMembership { GroupName = "group", MemberName = "host-d" }
            ]),
            new StubAddressDefinitionLookup(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["host-a"] = "10.0.0.1/32",
                ["host-b"] = "10.0.0.2/32",
                ["host-c"] = "10.0.0.3/32",
                ["host-d"] = "10.0.0.4/32"
            }),
            new StubAddressGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["Group"] = ["host-a", "host-b"],
                ["group"] = ["host-c", "host-d"]
            }),
            rangeSplitThreshold: 10);

        var result = compactor.Compact(
        [
            new AddressValue { Start = 0x0A000003, Finish = 0x0A000003 },
            new AddressValue { Start = 0x0A000004, Finish = 0x0A000004 }
        ]);

        Assert.Equal(["group"], result.GroupNames);
        Assert.Empty(result.RemainingAddresses);
    }

    private sealed class StubAddressGroupRepository :
        IReadRepository<AddressGroupMembership>,
        ILookupRepository<IReadOnlyList<string>>
    {
        private readonly AddressGroupMembership[] members;
        private readonly Dictionary<string, IReadOnlyList<string>> groups;

        public StubAddressGroupRepository(IEnumerable<AddressGroupMembership> members)
        {
            this.members = members.ToArray();
            groups = this.members
                .GroupBy(static member => member.GroupName, StringComparer.Ordinal)
                .ToDictionary(
                    static group => group.Key,
                    static group => (IReadOnlyList<string>)group.Select(static member => member.MemberName).ToArray(),
                    StringComparer.Ordinal);
        }

        public IEnumerable<AddressGroupMembership> GetAll()
        {
            return members;
        }

        public bool TryGetByName(string name, out IReadOnlyList<string> value)
        {
            return groups.TryGetValue(name, out value!);
        }

        public void EnsureAvailable()
        {
        }
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

        public bool TryGetByName(string name, out IReadOnlyList<string> value)
        {
            return groups.TryGetValue(name, out value!);
        }

        public void EnsureAvailable()
        {
        }
    }
}
