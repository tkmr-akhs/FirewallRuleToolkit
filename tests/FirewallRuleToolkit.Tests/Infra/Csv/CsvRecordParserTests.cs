using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvRecordParserTests
{
    [Fact]
    public void ParseRecord_WithoutHeaders_UsesZeroBasedStringKeys()
    {
        var parser = new CsvRecordParser();

        var record = parser.ParseRecord("a,b,c");

        Assert.Equal("a", record["0"]);
        Assert.Equal("b", record["1"]);
        Assert.Equal("c", record["2"]);
    }

    [Fact]
    public void ParseRecord_WithHeaders_UsesHeaderNamesAsKeys()
    {
        var parser = new CsvRecordParser(headers: ["Name", "Port"]);

        var record = parser.ParseRecord("http,80");

        Assert.Equal("http", record["Name"]);
        Assert.Equal("80", record["Port"]);
    }

    [Fact]
    public void ParseRecord_QuotedField_UnescapesDoubleQuotes()
    {
        var parser = new CsvRecordParser();

        var record = parser.ParseRecord("\"a\"\"b\",c");

        Assert.Equal("a\"b", record["0"]);
        Assert.Equal("c", record["1"]);
    }

    [Fact]
    public void ParseRecord_HeaderCountMismatch_ThrowsFormatException()
    {
        var parser = new CsvRecordParser(headers: ["A"]);

        Assert.Throws<FormatException>(() => parser.ParseRecord("a,b"));
    }

    [Fact]
    public void ParseRecord_UnclosedQuotedField_ThrowsFormatException()
    {
        var parser = new CsvRecordParser();

        Assert.Throws<FormatException>(() => parser.ParseRecord("\"a,b"));
    }

    [Fact]
    public void ParseRecord_CharacterAfterClosingQuote_ThrowsFormatException()
    {
        var parser = new CsvRecordParser();

        Assert.Throws<FormatException>(() => parser.ParseRecord("\"a\"x,b"));
    }
}
