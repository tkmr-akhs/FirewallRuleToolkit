using System.IO;
using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvRecordReaderTests
{
    [Fact]
    public void ReadRecord_AutoDetectsLf()
    {
        using var reader = new StringReader("a,b\nc,d");
        var recordReader = new CsvRecordReader(reader);

        var first = recordReader.ReadRecord();
        var second = recordReader.ReadRecord();

        Assert.Equal("a,b", first);
        Assert.Equal("c,d", second);
    }

    [Fact]
    public void ReadRecord_QuotedFieldCanContainNewLine()
    {
        using var reader = new StringReader("\"a\nb\",c\nx,y");
        var recordReader = new CsvRecordReader(reader);

        var first = recordReader.ReadRecord();
        var second = recordReader.ReadRecord();

        Assert.Equal("\"a\nb\",c", first);
        Assert.Equal("x,y", second);
    }

    [Fact]
    public void ReadRecord_WithCrLfMode_ConsumesCrLfAsOneRecordTerminator()
    {
        using var reader = new StringReader("a,b\r\nc,d");
        var options = new CsvOptions { NewLineMode = CsvNewLineMode.CrLf };
        var recordReader = new CsvRecordReader(reader, options);

        var first = recordReader.ReadRecord();
        var second = recordReader.ReadRecord();

        Assert.Equal("a,b", first);
        Assert.Equal("c,d", second);
    }

    [Fact]
    public void ReadRecord_EofInsideQuotedField_ThrowsFormatException()
    {
        using var reader = new StringReader("\"a,b");
        var recordReader = new CsvRecordReader(reader);

        Assert.Throws<FormatException>(() => recordReader.ReadRecord());
    }
}
