using System.Text;
using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Tests.Infra.Csv;

public sealed class CsvFileWriterTests
{
    [Fact]
    public void WriteRecord_Fields_WritesCsvToFile()
    {
        var path = CreateTempFilePath();

        try
        {
            using (var writer = new CsvFileWriter(path, new CsvOptions { NewLineMode = CsvNewLineMode.Lf }))
            {
                writer.WriteRecord(["a,b", "c"]);
            }

            var content = File.ReadAllText(path, new UTF8Encoding(false));
            Assert.Equal("\"a,b\",\"c\"\n", content);
        }
        finally
        {
            DeleteIfExists(path);
        }
    }

    [Fact]
    public void WriteRecord_String_AfterDispose_ThrowsObjectDisposedException()
    {
        var path = CreateTempFilePath();

        try
        {
            var writer = new CsvFileWriter(path);
            writer.Dispose();

            Assert.Throws<ObjectDisposedException>(() => writer.WriteRecord("a,b"));
        }
        finally
        {
            DeleteIfExists(path);
        }
    }

    private static string CreateTempFilePath()
    {
        return Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.csv");
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
