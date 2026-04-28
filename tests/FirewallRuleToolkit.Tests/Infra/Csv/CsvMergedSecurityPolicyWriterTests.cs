using System.Text;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.Services;
using FirewallRuleToolkit.Infra.Csv;
using FirewallRuleToolkit.Infra.Csv.Lib;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvMergedSecurityPolicyWriterTests
{
    [Fact]
    public void ReplaceAll_WritesHumanReadableAddressAndServiceValues()
    {
        var path = CreateTempFilePath();

        try
        {
            IWriteRepository<MergedSecurityPolicy> writer = new CsvMergedSecurityPolicyWriter(path, new CsvOptions
            {
                NewLineMode = CsvNewLineMode.Lf,
                Encoding = new UTF8Encoding(false)
            });

            writer.ReplaceAll([
                new MergedSecurityPolicy
                {
                    FromZones = new HashSet<string>(StringComparer.Ordinal) { "z2", "z1" },
                    SourceAddresses = [
                        new AddressValue { Start = 0xC0A80100, Finish = 0xC0A801FF },
                        new AddressValue { Start = 0, Finish = uint.MaxValue }
                    ],
                    ToZones = new HashSet<string>(StringComparer.Ordinal) { "trust" },
                    DestinationAddresses = [
                        new AddressValue { Start = 0x0A000001, Finish = 0x0A00000A },
                        new AddressValue { Start = 0x0A000001, Finish = 0x0A000001 }
                    ],
                    Applications = new HashSet<string>(StringComparer.Ordinal) { "ssl", "web-browsing" },
                    Services = [
                        new ServiceValue
                        {
                            ProtocolStart = 6,
                            ProtocolFinish = 6,
                            SourcePortStart = 0,
                            SourcePortFinish = 65535,
                            DestinationPortStart = 80,
                            DestinationPortFinish = 90,
                            Kind = null
                        },
                        new ServiceValue
                        {
                            ProtocolStart = 0,
                            ProtocolFinish = 255,
                            SourcePortStart = 0,
                            SourcePortFinish = 65535,
                            DestinationPortStart = 0,
                            DestinationPortFinish = 65535,
                            Kind = null
                        },
                        new ServiceValue
                        {
                            ProtocolStart = 255,
                            ProtocolFinish = 255,
                            SourcePortStart = 0,
                            SourcePortFinish = 0,
                            DestinationPortStart = 0,
                            DestinationPortFinish = 0,
                            Kind = "application-default"
                        }
                    ],
                    Action = SecurityPolicyAction.Allow,
                    GroupId = "G1",
                    MinimumIndex = 10,
                    MaximumIndex = 99,
                    OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { "p2", "p1" }
                }
            ]);

            var content = File.ReadAllText(path, new UTF8Encoding(false));
            var expected = string.Join(
                '\n',
                [
                    "\"from_zones\",\"source_addresses\",\"to_zones\",\"destination_addresses\",\"applications\",\"services\",\"action\",\"group_id\",\"minimum_index\",\"maximum_index\",\"original_policy_names\"",
                    "\"z1, z2\",\"192.168.1.0/24, any\",\"trust\",\"10.0.0.1-10.0.0.10, 10.0.0.1/32\",\"ssl, web-browsing\",\"any, application-default, tcp any 80-90\",\"Allow\",\"G1\",\"10\",\"99\",\"p1, p2\"",
                    string.Empty
                ]);

            Assert.Equal(expected, content);
        }
        finally
        {
            DeleteIfExists(path);
        }
    }

    [Fact]
    public void ReplaceAll_WhenServiceValueUsesAxisAnyRanges_WritesThreePartAny()
    {
        var path = CreateTempFilePath();

        try
        {
            IWriteRepository<MergedSecurityPolicy> writer = new CsvMergedSecurityPolicyWriter(path, new CsvOptions
            {
                NewLineMode = CsvNewLineMode.Lf,
                Encoding = new UTF8Encoding(false)
            });

            writer.ReplaceAll([
                new MergedSecurityPolicy
                {
                    FromZones = new HashSet<string>(StringComparer.Ordinal) { "trust" },
                    SourceAddresses = [
                        new AddressValue { Start = 0, Finish = uint.MaxValue }
                    ],
                    ToZones = new HashSet<string>(StringComparer.Ordinal) { "untrust" },
                    DestinationAddresses = [
                        new AddressValue { Start = 0, Finish = uint.MaxValue }
                    ],
                    Applications = new HashSet<string>(StringComparer.Ordinal) { "any" },
                    Services = [
                        new ServiceValue
                        {
                            ProtocolStart = 0,
                            ProtocolFinish = 254,
                            SourcePortStart = 1,
                            SourcePortFinish = 65535,
                            DestinationPortStart = 1,
                            DestinationPortFinish = 65535,
                            Kind = null
                        }
                    ],
                    Action = SecurityPolicyAction.Allow,
                    GroupId = string.Empty,
                    MinimumIndex = 1,
                    MaximumIndex = 1,
                    OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { "p1" }
                }
            ]);

            var content = File.ReadAllText(path, new UTF8Encoding(false));

            Assert.Contains("\"any any any\"", content, StringComparison.Ordinal);
        }
        finally
        {
            DeleteIfExists(path);
        }
    }

    [Fact]
    public void ReplaceAll_WhenProtocolRangeDoesNotCoverAny_WritesProtocolRange()
    {
        var path = CreateTempFilePath();

        try
        {
            IWriteRepository<MergedSecurityPolicy> writer = new CsvMergedSecurityPolicyWriter(path, new CsvOptions
            {
                NewLineMode = CsvNewLineMode.Lf,
                Encoding = new UTF8Encoding(false)
            });

            writer.ReplaceAll([
                new MergedSecurityPolicy
                {
                    FromZones = new HashSet<string>(StringComparer.Ordinal) { "trust" },
                    SourceAddresses = [
                        new AddressValue { Start = 0, Finish = uint.MaxValue }
                    ],
                    ToZones = new HashSet<string>(StringComparer.Ordinal) { "untrust" },
                    DestinationAddresses = [
                        new AddressValue { Start = 0, Finish = uint.MaxValue }
                    ],
                    Applications = new HashSet<string>(StringComparer.Ordinal) { "any" },
                    Services = [
                        new ServiceValue
                        {
                            ProtocolStart = 0,
                            ProtocolFinish = 245,
                            SourcePortStart = 0,
                            SourcePortFinish = 65535,
                            DestinationPortStart = 0,
                            DestinationPortFinish = 65535,
                            Kind = null
                        }
                    ],
                    Action = SecurityPolicyAction.Allow,
                    GroupId = string.Empty,
                    MinimumIndex = 1,
                    MaximumIndex = 1,
                    OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { "p1" }
                }
            ]);

            var content = File.ReadAllText(path, new UTF8Encoding(false));

            Assert.Contains("\"0-245 any any\"", content, StringComparison.Ordinal);
        }
        finally
        {
            DeleteIfExists(path);
        }
    }

    [Fact]
    public void ReplaceAll_WhenProtocolRangeEndpointsHaveKnownNames_WritesNumericProtocolRange()
    {
        var path = CreateTempFilePath();

        try
        {
            IWriteRepository<MergedSecurityPolicy> writer = new CsvMergedSecurityPolicyWriter(path, new CsvOptions
            {
                NewLineMode = CsvNewLineMode.Lf,
                Encoding = new UTF8Encoding(false)
            });

            writer.ReplaceAll([
                new MergedSecurityPolicy
                {
                    FromZones = new HashSet<string>(StringComparer.Ordinal) { "trust" },
                    SourceAddresses = [
                        new AddressValue { Start = 0, Finish = uint.MaxValue }
                    ],
                    ToZones = new HashSet<string>(StringComparer.Ordinal) { "untrust" },
                    DestinationAddresses = [
                        new AddressValue { Start = 0, Finish = uint.MaxValue }
                    ],
                    Applications = new HashSet<string>(StringComparer.Ordinal) { "any" },
                    Services = [
                        new ServiceValue
                        {
                            ProtocolStart = 1,
                            ProtocolFinish = 17,
                            SourcePortStart = 0,
                            SourcePortFinish = 65535,
                            DestinationPortStart = 0,
                            DestinationPortFinish = 65535,
                            Kind = null
                        }
                    ],
                    Action = SecurityPolicyAction.Allow,
                    GroupId = string.Empty,
                    MinimumIndex = 1,
                    MaximumIndex = 1,
                    OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { "p1" }
                }
            ]);

            var content = File.ReadAllText(path, new UTF8Encoding(false));

            Assert.Contains("\"1-17 any any\"", content, StringComparison.Ordinal);
            Assert.DoesNotContain("icmp-udp", content, StringComparison.Ordinal);
        }
        finally
        {
            DeleteIfExists(path);
        }
    }

    [Fact]
    public void ReplaceAll_WhenSourceAddressesMatchImportedGroup_WritesGroupNamePlusRemainingAddresses()
    {
        var path = CreateTempFilePath();

        try
        {
            var compactor = new AddressGroupCompactor(
                new StubAddressGroupRepository(
                [
                    new AddressGroupMembership { GroupName = "src-group", MemberName = "host-a" },
                    new AddressGroupMembership { GroupName = "src-group", MemberName = "host-b" }
                ]),
                new StubAddressDefinitionLookup(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["host-a"] = "192.168.1.10/32",
                    ["host-b"] = "192.168.1.11/32"
                }),
                new StubAddressGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    ["src-group"] = ["host-a", "host-b"]
                }),
                rangeSplitThreshold: 10);

            var writer = new CsvMergedSecurityPolicyWriter(path, new CsvOptions
            {
                NewLineMode = CsvNewLineMode.Lf,
                Encoding = new UTF8Encoding(false)
            }, compactor);

            writer.ReplaceAll([
                new MergedSecurityPolicy
                {
                    FromZones = new HashSet<string>(StringComparer.Ordinal) { "trust" },
                    SourceAddresses = [
                        new AddressValue { Start = 0xC0A8010A, Finish = 0xC0A8010A },
                        new AddressValue { Start = 0xC0A8010B, Finish = 0xC0A8010B },
                        new AddressValue { Start = 0xC0A80163, Finish = 0xC0A80163 }
                    ],
                    ToZones = new HashSet<string>(StringComparer.Ordinal) { "untrust" },
                    DestinationAddresses = [
                        new AddressValue { Start = 0x0A000001, Finish = 0x0A000001 }
                    ],
                    Applications = new HashSet<string>(StringComparer.Ordinal) { "ssl" },
                    Services = [
                        new ServiceValue
                        {
                            ProtocolStart = 6,
                            ProtocolFinish = 6,
                            SourcePortStart = 0,
                            SourcePortFinish = 65535,
                            DestinationPortStart = 443,
                            DestinationPortFinish = 443,
                            Kind = null
                        }
                    ],
                    Action = SecurityPolicyAction.Allow,
                    GroupId = "G2",
                    MinimumIndex = 1,
                    MaximumIndex = 2,
                    OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { "p1" }
                }
            ]);

            var content = File.ReadAllText(path, new UTF8Encoding(false));
            Assert.Contains("\"src-group, 192.168.1.99/32\"", content);
        }
        finally
        {
            DeleteIfExists(path);
        }
    }

    [Fact]
    public void ReplaceAll_WhenDestinationAddressesMatchImportedGroup_WritesGroupNamePlusRemainingAddresses()
    {
        var path = CreateTempFilePath();

        try
        {
            var compactor = new AddressGroupCompactor(
                new StubAddressGroupRepository(
                [
                    new AddressGroupMembership { GroupName = "dst-group", MemberName = "host-a" },
                    new AddressGroupMembership { GroupName = "dst-group", MemberName = "host-b" }
                ]),
                new StubAddressDefinitionLookup(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["host-a"] = "10.0.0.10/32",
                    ["host-b"] = "10.0.0.11/32"
                }),
                new StubAddressGroupLookup(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    ["dst-group"] = ["host-a", "host-b"]
                }),
                rangeSplitThreshold: 10);

            var writer = new CsvMergedSecurityPolicyWriter(path, new CsvOptions
            {
                NewLineMode = CsvNewLineMode.Lf,
                Encoding = new UTF8Encoding(false)
            }, compactor);

            writer.ReplaceAll([
                new MergedSecurityPolicy
                {
                    FromZones = new HashSet<string>(StringComparer.Ordinal) { "trust" },
                    SourceAddresses = [
                        new AddressValue { Start = 0xC0A8010A, Finish = 0xC0A8010A }
                    ],
                    ToZones = new HashSet<string>(StringComparer.Ordinal) { "untrust" },
                    DestinationAddresses = [
                        new AddressValue { Start = 0x0A00000A, Finish = 0x0A00000A },
                        new AddressValue { Start = 0x0A00000B, Finish = 0x0A00000B },
                        new AddressValue { Start = 0x0A000063, Finish = 0x0A000063 }
                    ],
                    Applications = new HashSet<string>(StringComparer.Ordinal) { "ssl" },
                    Services = [
                        new ServiceValue
                        {
                            ProtocolStart = 6,
                            ProtocolFinish = 6,
                            SourcePortStart = 0,
                            SourcePortFinish = 65535,
                            DestinationPortStart = 443,
                            DestinationPortFinish = 443,
                            Kind = null
                        }
                    ],
                    Action = SecurityPolicyAction.Allow,
                    GroupId = "G3",
                    MinimumIndex = 3,
                    MaximumIndex = 4,
                    OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { "p2" }
                }
            ]);

            var content = File.ReadAllText(path, new UTF8Encoding(false));
            Assert.Contains("\"dst-group, 10.0.0.99/32\"", content);
        }
        finally
        {
            DeleteIfExists(path);
        }
    }

    private static string CreateTempFilePath()
    {
        return Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.csv");
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
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
