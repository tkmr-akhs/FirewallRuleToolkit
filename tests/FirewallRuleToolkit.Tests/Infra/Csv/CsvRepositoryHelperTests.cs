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
            "from_zone,source_address_json,to_zone,destination_address_json,application,service_json,action,group_id,original_index,original_policy_name\r\n" +
            "trust,not-json,untrust,\"{\"\"s\"\":1,\"\"f\"\":1}\",any,\"{\"\"proto\"\":6,\"\"src\"\":1,\"\"dst\"\":80}\",Allow,group-1,1,rule-1",
            new UTF8Encoding(false));

        try
        {
            var repository = new CsvAtomicPolicyRepository(path);

            var exception = Assert.Throws<RepositoryReadException>(() => repository.GetAll().ToArray());

            Assert.Contains(path, exception.Message, StringComparison.Ordinal);
            Assert.Contains("record: 2", exception.Message, StringComparison.Ordinal);
            Assert.IsAssignableFrom<System.Text.Json.JsonException>(exception.InnerException);
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
