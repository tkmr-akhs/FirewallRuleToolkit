using System.Text;
using FirewallRuleToolkit.Domain.Exceptions;
using FirewallRuleToolkit.Infra.Csv.PaloAlto;

namespace FirewallRuleToolkit.Tests.Infra.Csv.PaloAlto;

public sealed class PaloAltoCsvReadersTests
{
    private const string HeaderName = "\u540D\u524D";
    private const string HeaderAddress = "\u30A2\u30C9\u30EC\u30B9";
    private const string HeaderProtocol = "\u30D7\u30ED\u30C8\u30B3\u30EB";
    private const string HeaderSourcePort = "\u9001\u4FE1\u5143\u30DD\u30FC\u30C8";
    private const string HeaderDestinationPort = "\u5B9B\u5148\u30DD\u30FC\u30C8";
    private const string HeaderFromZone = "\u9001\u4FE1\u5143 \u30BE\u30FC\u30F3";
    private const string HeaderSourceAddress = "\u9001\u4FE1\u5143 \u30A2\u30C9\u30EC\u30B9";
    private const string HeaderToZone = "\u5B9B\u5148 \u30BE\u30FC\u30F3";
    private const string HeaderDestinationAddress = "\u5B9B\u5148 \u30A2\u30C9\u30EC\u30B9";
    private const string HeaderApplication = "\u30A2\u30D7\u30EA\u30B1\u30FC\u30B7\u30E7\u30F3";
    private const string HeaderService = "\u30B5\u30FC\u30D3\u30B9";
    private const string HeaderAction = "\u30A2\u30AF\u30B7\u30E7\u30F3";
    private const string HeaderRuleUsageContent = "\u30EB\u30FC\u30EB\u306E\u4F7F\u7528\u72B6\u6CC1 \u5185\u5BB9";

    [Fact]
    public void GetAll_NormalizesHostAddressToCidr()
    {
        var path = CreateTempFile(
            $"{HeaderName},{HeaderAddress}\nhost-1,192.168.10.20\nrange-1,192.168.10.20-192.168.10.30",
            new UTF8Encoding(false));

        try
        {
            var reader = new PaloAltoAddressObjectCsvReader(path);

            var objects = reader.GetAll().ToArray();

            Assert.Collection(
                objects,
                item =>
                {
                    Assert.Equal("host-1", item.Name);
                    Assert.Equal("192.168.10.20/32", item.Value);
                },
                item =>
                {
                    Assert.Equal("range-1", item.Name);
                    Assert.Equal("192.168.10.20-192.168.10.30", item.Value);
                });
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void GetAll_NormalizesProtocolAndPortAliases()
    {
        var path = CreateTempFile(
            $"{HeaderName},{HeaderProtocol},{HeaderSourcePort},{HeaderDestinationPort}\nsvc-web,TCP,any,443\nsvc-range,17,1,0-65535\nsvc-zero-range,6,0-1023,0-2048\nsvc-composite,udp,\"1,0-7,8\",\"0,443,1000-1002\"\nsvc-upper-any,TCP,ANY,ANY",
            new UTF8Encoding(false));

        try
        {
            var reader = new PaloAltoServiceObjectCsvReader(path);

            var objects = reader.GetAll().ToArray();

            Assert.Collection(
                objects,
                item =>
                {
                    Assert.Equal("svc-web", item.Name);
                    Assert.Equal("6", item.Protocol);
                    Assert.Equal("1-65535", item.SourcePort);
                    Assert.Equal("443", item.DestinationPort);
                },
                item =>
                {
                    Assert.Equal("svc-range", item.Name);
                    Assert.Equal("17", item.Protocol);
                    Assert.Equal("1", item.SourcePort);
                    Assert.Equal("1-65535", item.DestinationPort);
                },
                item =>
                {
                    Assert.Equal("svc-zero-range", item.Name);
                    Assert.Equal("6", item.Protocol);
                    Assert.Equal("1-1023", item.SourcePort);
                    Assert.Equal("1-2048", item.DestinationPort);
                },
                item =>
                {
                    Assert.Equal("svc-composite", item.Name);
                    Assert.Equal("17", item.Protocol);
                    Assert.Equal("1,1-7,8", item.SourcePort);
                    Assert.Equal("1,443,1000-1002", item.DestinationPort);
                },
                item =>
                {
                    Assert.Equal("svc-upper-any", item.Name);
                    Assert.Equal("6", item.Protocol);
                    Assert.Equal("1-65535", item.SourcePort);
                    Assert.Equal("1-65535", item.DestinationPort);
                });
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void GetAll_GroupIdUsesFirstSegmentWhenPipeExistsOtherwiseEmpty()
    {
        var path = CreateTempFile(
            $",{HeaderName},{HeaderFromZone},{HeaderSourceAddress},{HeaderToZone},{HeaderDestinationAddress},{HeaderApplication},{HeaderService},{HeaderAction},{HeaderRuleUsageContent}\n" +
            $"1,rule-1,trust,src-group;10.0.0.0/24,untrust,dst-host,any,svc-group;TCP 1-65535 80,\u8A31\u53EF,GRP-01|memo\n" +
            $"2,rule-2,trust,10.0.1.0/24,untrust,192.168.1.10,any,any,\u8A31\u53EF,no-separator\n" +
            $"3,rule-3,trust,10.0.2.0/24,untrust,192.168.2.10,any,any,\u8A31\u53EF,",
            new UTF8Encoding(false));

        try
        {
            var reader = new PaloAltoSecurityPolicyCsvReader(path);

            var policies = reader.GetAll().ToArray();

            Assert.Equal(3, policies.Length);
            Assert.Equal("GRP-01", policies[0].GroupId);
            Assert.Equal(["src-group", "10.0.0.0/24"], policies[0].SourceAddressReferences);
            Assert.Equal(["dst-host"], policies[0].DestinationAddressReferences);
            Assert.Equal(["svc-group", "TCP 1-65535 80"], policies[0].ServiceReferences);
            Assert.Equal(string.Empty, policies[1].GroupId);
            Assert.Equal(string.Empty, policies[2].GroupId);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("999999999999999999999999999999", "\u8A31\u53EF", typeof(OverflowException))]
    [InlineData("1", "invalid-action", typeof(ArgumentException))]
    public void GetAll_WhenSecurityPolicyValueConversionFails_ThrowsRepositoryReadException(
        string index,
        string action,
        Type expectedInnerExceptionType)
    {
        var path = CreateTempFile(
            $",{HeaderName},{HeaderFromZone},{HeaderSourceAddress},{HeaderToZone},{HeaderDestinationAddress},{HeaderApplication},{HeaderService},{HeaderAction},{HeaderRuleUsageContent}\n" +
            $"{index},rule-1,trust,any,untrust,any,any,any,{action},",
            new UTF8Encoding(false));

        try
        {
            var reader = new PaloAltoSecurityPolicyCsvReader(path);

            var exception = Assert.Throws<RepositoryReadException>(() => reader.GetAll().ToArray());

            Assert.Contains(path, exception.Message, StringComparison.Ordinal);
            Assert.Contains("record: 2", exception.Message, StringComparison.Ordinal);
            Assert.Equal(expectedInnerExceptionType, exception.InnerException?.GetType());
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string CreateTempFile(string content, Encoding encoding)
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.csv");
        File.WriteAllText(path, content, encoding);
        return path;
    }
}
