namespace FirewallRuleToolkit.Tests;

public sealed class ProgramTests
{
    [Fact]
    public void NormalizeArguments_WhenLongOptionUsesEquals_LowercasesOnlyOptionName()
    {
        var normalized = Program.NormalizeArguments(
        [
            "stat",
            "--DATABASE=Tmp-DB",
            "--LOGFILE=C:\\Logs\\App.Log",
            "--LOGLEVEL=Debug"
        ]);

        Assert.Equal(
        [
            "stat",
            "--database=Tmp-DB",
            "--logfile=C:\\Logs\\App.Log",
            "--loglevel=Debug"
        ],
        normalized);
    }

    [Fact]
    public void NormalizeArguments_WhenLongOptionUsesSeparatedValue_LowercasesOnlyOptionToken()
    {
        var normalized = Program.NormalizeArguments(
        [
            "stat",
            "--DATABASE",
            "Tmp-DB"
        ]);

        Assert.Equal(
        [
            "stat",
            "--database",
            "Tmp-DB"
        ],
        normalized);
    }
}
