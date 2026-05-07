using System.Text;
using FirewallRuleToolkit.Domain.Exceptions;
using FirewallRuleToolkit.Infra.Csv;
using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvRepositoryHelperTests
{
    [Fact]
    public void ReadRows_WhenCsvFormatIsInvalid_ThrowsRepositoryReadExceptionWithRecordContext()
    {
        var path = CreateTempFile("Name,Port\r\n\"svc\"x,80", new UTF8Encoding(false));

        try
        {
            var exception = Assert.Throws<RepositoryReadException>(() =>
                CsvRepositoryHelper.ReadRows(path, new CsvOptions()).ToArray());

            Assert.Contains(path, exception.Message, StringComparison.Ordinal);
            Assert.Contains("record: 2", exception.Message, StringComparison.Ordinal);
            Assert.IsType<FormatException>(exception.InnerException);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CsvReadWriteRepositoryBaseGetAll_WhenRowConversionFails_ThrowsRepositoryReadExceptionWithRecordContext()
    {
        var path = CreateTempFile(
            "from_zone,source_address_start,source_address_finish,to_zone,destination_address_start,destination_address_finish,application,service_protocol_start,service_protocol_finish,service_source_port_start,service_source_port_finish,service_destination_port_start,service_destination_port_finish,service_kind,action,group_id,original_index,original_policy_name\r\n" +
            "trust,not-number,1,untrust,1,1,any,6,6,0,65535,80,80,,Allow,group-1,1,rule-1",
            new UTF8Encoding(false));

        try
        {
            var repository = new CsvAtomicPolicyRepository(path);

            var exception = Assert.Throws<RepositoryReadException>(() => repository.GetAll().ToArray());

            Assert.Contains(path, exception.Message, StringComparison.Ordinal);
            Assert.Contains("record: 2", exception.Message, StringComparison.Ordinal);
            Assert.IsType<FormatException>(exception.InnerException);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string CreateTempFile(string content, Encoding encoding)
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        File.WriteAllText(path, content, encoding);
        return path;
    }
}
