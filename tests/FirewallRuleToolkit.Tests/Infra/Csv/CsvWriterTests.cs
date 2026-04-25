using System.IO;
using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvWriterTests
{
    [Fact]
    public void WriteRecord_String_WritesRecordAndConfiguredNewLine()
    {
        using var textWriter = new StringWriter();
        using var writer = new CsvWriter(textWriter, new CsvOptions { NewLineMode = CsvNewLineMode.Lf });

        writer.WriteRecord("a,b");

        Assert.Equal("a,b\n", textWriter.ToString());
    }

    [Fact]
    public void WriteRecord_Fields_FormatsAndWritesRecord()
    {
        using var textWriter = new StringWriter();
        using var writer = new CsvWriter(textWriter, new CsvOptions { NewLineMode = CsvNewLineMode.CrLf });

        writer.WriteRecord(["a,b", "c"]);

        Assert.Equal("\"a,b\",\"c\"\r\n", textWriter.ToString());
    }

    [Fact]
    public void WriteRecord_AfterDispose_ThrowsObjectDisposedException()
    {
        using var textWriter = new StringWriter();
        var writer = new CsvWriter(textWriter);
        writer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => writer.WriteRecord("a,b"));
    }
}
