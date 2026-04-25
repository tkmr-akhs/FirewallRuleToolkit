using System.Text;
using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvFileReaderTests
{
    [Fact]
    public void ReadRows_WithFirstRowAsHeader_UsesHeaderKeys()
    {
        var path = CreateTempFile("Name,Port\nhttp,80\nhttps,443", new UTF8Encoding(false));

        try
        {
            using var reader = new CsvFileReader(path, useFirstRowAsHeader: true);

            var rows = reader.ReadRows().ToList();

            Assert.Equal(2, rows.Count);
            Assert.Equal("http", rows[0]["Name"]);
            Assert.Equal("443", rows[1]["Port"]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ReadRow_WithBomEnabled_ReadsUtf8BomFile()
    {
        var path = CreateTempFile("a,b", new UTF8Encoding(true));

        try
        {
            var options = new CsvOptions
            {
                Encoding = new UTF8Encoding(false),
                HasByteOrderMarks = true
            };

            using var reader = new CsvFileReader(path, options);

            var row = reader.ReadRow();

            Assert.NotNull(row);
            Assert.Equal("a", row["0"]);
            Assert.Equal("b", row["1"]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ReadRow_AfterDispose_ThrowsObjectDisposedException()
    {
        var path = CreateTempFile("a,b", new UTF8Encoding(false));

        try
        {
            var reader = new CsvFileReader(path);
            reader.Dispose();

            Assert.Throws<ObjectDisposedException>(() => reader.ReadRow());
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
