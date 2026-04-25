using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvRecordFormatterTests
{
    [Fact]
    public void FormatRecord_WithoutSpecialCharacters_JoinsFields()
    {
        var formatter = new CsvRecordFormatter();

        var record = formatter.FormatRecord(["a", "b", "c"]);

        Assert.Equal("\"a\",\"b\",\"c\"", record);
    }

    [Fact]
    public void FormatRecord_FieldContainingDelimiter_QuotesField()
    {
        var formatter = new CsvRecordFormatter();

        var record = formatter.FormatRecord(["a,b", "c"]);

        Assert.Equal("\"a,b\",\"c\"", record);
    }

    [Fact]
    public void FormatRecord_FieldContainingQuote_EscapesAndQuotesField()
    {
        var formatter = new CsvRecordFormatter();

        var record = formatter.FormatRecord(["a\"b", "c"]);

        Assert.Equal("\"a\"\"b\",\"c\"", record);
    }

    [Fact]
    public void FormatRecord_FieldContainingNewLine_QuotesField()
    {
        var formatter = new CsvRecordFormatter();

        var record = formatter.FormatRecord(["a\nb", "c"]);

        Assert.Equal("\"a\nb\",\"c\"", record);
    }

    [Fact]
    public void FormatRecord_WithCustomDelimiter_UsesOptions()
    {
        var formatter = new CsvRecordFormatter(new CsvOptions { Delimiter = ';' });

        var record = formatter.FormatRecord(["a;b", "c"]);

        Assert.Equal("\"a;b\";\"c\"", record);
    }
}
