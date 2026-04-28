using FirewallRuleToolkit.Domain.Services.PolicyConditions;
using FirewallRuleToolkit.Domain.ValueObjects;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class PolicyConditionCanonicalOrderTests
{
    [Fact]
    public void OrderAddresses_OrdersByNumericStartAndFinish()
    {
        var values = new[]
        {
            new AddressValue { Start = 10, Finish = 20 },
            new AddressValue { Start = 1, Finish = 100 },
            new AddressValue { Start = 1, Finish = 10 }
        };

        var ordered = PolicyConditionCanonicalOrder
            .OrderAddresses(values)
            .Select(static value => (value.Start, value.Finish))
            .ToArray();

        Assert.Equal(
        [
            (1U, 10U),
            (1U, 100U),
            (10U, 20U)
        ],
        ordered);
    }

    [Fact]
    public void OrderServices_OrdersByAnyKindThenProtocolDestinationAndSource()
    {
        var any = CreateService(0, 255, 0, 65535, 0, 65535);
        var kind = CreateService(255, 255, 0, 0, 0, 0, "application-default");
        var udp80 = CreateService(17, 17, 10, 10, 80, 80);
        var tcp443Source10 = CreateService(6, 6, 10, 10, 443, 443);
        var tcp443Source20 = CreateService(6, 6, 20, 20, 443, 443);
        var tcp80 = CreateService(6, 6, 65535, 65535, 80, 80);

        var values = new Dictionary<string, ServiceValue>(StringComparer.Ordinal)
        {
            ["udp80"] = udp80,
            ["tcp443-source20"] = tcp443Source20,
            ["kind"] = kind,
            ["tcp80"] = tcp80,
            ["any"] = any,
            ["tcp443-source10"] = tcp443Source10
        };

        var orderedNames = PolicyConditionCanonicalOrder
            .OrderServices(values.Values)
            .Select(value => values.Single(pair => pair.Value.Equals(value)).Key)
            .ToArray();

        Assert.Equal(
        [
            "any",
            "kind",
            "tcp80",
            "tcp443-source10",
            "tcp443-source20",
            "udp80"
        ],
        orderedNames);
    }

    private static ServiceValue CreateService(
        uint protocolStart,
        uint protocolFinish,
        uint sourcePortStart,
        uint sourcePortFinish,
        uint destinationPortStart,
        uint destinationPortFinish,
        string? kind = null)
    {
        return new ServiceValue
        {
            ProtocolStart = protocolStart,
            ProtocolFinish = protocolFinish,
            SourcePortStart = sourcePortStart,
            SourcePortFinish = sourcePortFinish,
            DestinationPortStart = destinationPortStart,
            DestinationPortFinish = destinationPortFinish,
            Kind = kind
        };
    }
}
