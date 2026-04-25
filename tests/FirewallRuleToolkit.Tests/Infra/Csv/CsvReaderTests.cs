using System.IO;
using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvReaderTests
{
    [Fact]
    public void ReadRow_WithoutHeaderRow_ReturnsIndexedKeys()
    {
        using var source = new StringReader("a,b");
        using var reader = new CsvReader(source);

        var row = reader.ReadRow();

        Assert.NotNull(row);
        Assert.Equal("a", row["0"]);
        Assert.Equal("b", row["1"]);
    }

    [Fact]
    public void ReadRows_WithFirstRowAsHeader_UsesHeaderKeys()
    {
        using var source = new StringReader("Name,Port\nhttp,80\nhttps,443");
        using var reader = new CsvReader(source, useFirstRowAsHeader: true);

        var rows = reader.ReadRows().ToList();

        Assert.Equal(2, rows.Count);
        Assert.Equal("http", rows[0]["Name"]);
        Assert.Equal("80", rows[0]["Port"]);
        Assert.Equal("https", rows[1]["Name"]);
        Assert.Equal("443", rows[1]["Port"]);
    }

    [Fact]
    public void ReadRow_AfterDispose_ThrowsObjectDisposedException()
    {
        using var source = new StringReader("a,b");
        var reader = new CsvReader(source);
        reader.Dispose();

        Assert.Throws<ObjectDisposedException>(() => reader.ReadRow());
    }
}
