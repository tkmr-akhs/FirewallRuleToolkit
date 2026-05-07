using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;
using FirewallRuleToolkit.Infra.Csv;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvAtomicPolicyRepositoryTests
{
    [Fact]
    public void ReplaceAll_WritesAndReadsScalarConditionColumns()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

        try
        {
            var repository = new CsvAtomicPolicyRepository(path);
            repository.ReplaceAll(
            [
                new AtomicSecurityPolicy
                {
                    FromZone = "trust",
                    SourceAddress = new AddressValue { Start = 100, Finish = 101 },
                    ToZone = "untrust",
                    DestinationAddress = new AddressValue { Start = 200, Finish = 201 },
                    Application = "web-browsing",
                    Service = new ServiceValue
                    {
                        ProtocolStart = 6,
                        ProtocolFinish = 6,
                        SourcePortStart = 1024,
                        SourcePortFinish = 2048,
                        DestinationPortStart = 443,
                        DestinationPortFinish = 444,
                        Kind = "service-a"
                    },
                    Action = SecurityPolicyAction.Allow,
                    GroupId = "group-1",
                    OriginalIndex = 10,
                    OriginalPolicyName = "rule-1"
                }
            ]);

            var content = File.ReadAllText(path);
            Assert.Contains("\"source_address_start\"", content, StringComparison.Ordinal);
            Assert.Contains("\"destination_address_start\"", content, StringComparison.Ordinal);
            Assert.Contains("\"service_protocol_start\"", content, StringComparison.Ordinal);
            Assert.Contains("\"service_kind\"", content, StringComparison.Ordinal);
            Assert.DoesNotContain("source_address_json", content, StringComparison.Ordinal);
            Assert.DoesNotContain("destination_address_json", content, StringComparison.Ordinal);
            Assert.DoesNotContain("service_json", content, StringComparison.Ordinal);

            var restored = repository.GetAll().Single();
            Assert.Equal(100U, restored.SourceAddress.Start);
            Assert.Equal(101U, restored.SourceAddress.Finish);
            Assert.Equal(200U, restored.DestinationAddress.Start);
            Assert.Equal(201U, restored.DestinationAddress.Finish);
            Assert.Equal(6U, restored.Service.ProtocolStart);
            Assert.Equal(6U, restored.Service.ProtocolFinish);
            Assert.Equal(1024U, restored.Service.SourcePortStart);
            Assert.Equal(2048U, restored.Service.SourcePortFinish);
            Assert.Equal(443U, restored.Service.DestinationPortStart);
            Assert.Equal(444U, restored.Service.DestinationPortFinish);
            Assert.Equal("service-a", restored.Service.Kind);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
