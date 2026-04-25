using System.Text;
using FirewallRuleToolkit.App;
using FirewallRuleToolkit.App.Composition;
using FirewallRuleToolkit.Domain.Exceptions;

namespace FirewallRuleToolkit.Tests.App;

public sealed class ImportCompositionTests
{
    [Fact]
    public void Run_WhenCsvReadFails_ThrowsApplicationUsageExceptionWithCsvContext()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var databaseDirectory = Path.Combine(temporaryDirectory, "db");
            var addressesPath = WriteCsv(temporaryDirectory, "addresses.csv", "名前,アドレス\r\nsrc,192.168.1.1");
            var addressGroupsPath = WriteCsv(temporaryDirectory, "address-groups.csv", "名前,アドレス\r\nsrc-group,src");
            var servicesPath = WriteCsv(temporaryDirectory, "services.csv", "名前,プロトコル,送信元ポート,宛先ポート\r\n\"svc\"x,TCP,any,80");
            var serviceGroupsPath = WriteCsv(temporaryDirectory, "service-groups.csv", "名前,サービス\r\nsvc-group,svc");
            var securityPoliciesPath = WriteCsv(
                temporaryDirectory,
                "security-policies.csv",
                ",名前,送信元 ゾーン,送信元 アドレス,宛先 ゾーン,宛先 アドレス,アプリケーション,サービス,アクション,ルールの使用状況 内容\r\n" +
                "1,rule-1,trust,src,untrust,any,any,svc,許可,");

            var exception = Assert.Throws<ApplicationUsageException>(() =>
                ImportComposition.Run(
                    databaseDirectory,
                    Encoding.UTF8,
                    securityPoliciesPath,
                    addressesPath,
                    addressGroupsPath,
                    servicesPath,
                    serviceGroupsPath));

            Assert.Contains("CSV の読み取りに失敗しました。", exception.Message, StringComparison.Ordinal);
            Assert.Contains(servicesPath, exception.Message, StringComparison.Ordinal);
            Assert.Contains("record: 2", exception.Message, StringComparison.Ordinal);
            Assert.IsType<RepositoryReadException>(exception.InnerException);
        }
        finally
        {
            DeleteDirectoryWithRetry(temporaryDirectory);
        }
    }

    [Fact]
    public void Run_WhenCsvFileIsMissing_ThrowsApplicationUsageExceptionWithCsvContext()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var databaseDirectory = Path.Combine(temporaryDirectory, "db");
            var addressesPath = WriteCsv(temporaryDirectory, "addresses.csv", "名前,アドレス\r\nsrc,192.168.1.1");
            var addressGroupsPath = WriteCsv(temporaryDirectory, "address-groups.csv", "名前,アドレス\r\nsrc-group,src");
            var servicesPath = Path.Combine(temporaryDirectory, "missing-services.csv");
            var serviceGroupsPath = WriteCsv(temporaryDirectory, "service-groups.csv", "名前,サービス\r\nsvc-group,svc");
            var securityPoliciesPath = WriteCsv(
                temporaryDirectory,
                "security-policies.csv",
                ",名前,送信元 ゾーン,送信元 アドレス,宛先 ゾーン,宛先 アドレス,アプリケーション,サービス,アクション,ルールの使用状況 内容\r\n" +
                "1,rule-1,trust,src,untrust,any,any,svc,許可,");

            var exception = Assert.Throws<ApplicationUsageException>(() =>
                ImportComposition.Run(
                    databaseDirectory,
                    Encoding.UTF8,
                    securityPoliciesPath,
                    addressesPath,
                    addressGroupsPath,
                    servicesPath,
                    serviceGroupsPath));

            Assert.Contains("CSV の読み取りに失敗しました。", exception.Message, StringComparison.Ordinal);
            Assert.Contains(servicesPath, exception.Message, StringComparison.Ordinal);
            Assert.IsType<RepositoryUnavailableException>(exception.InnerException);
        }
        finally
        {
            DeleteDirectoryWithRetry(temporaryDirectory);
        }
    }

    private static string WriteCsv(string directory, string fileName, string content)
    {
        var path = Path.Combine(directory, fileName);
        File.WriteAllText(path, content, new UTF8Encoding(false));
        return path;
    }

    private static void DeleteDirectoryWithRetry(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        try
        {
            Directory.Delete(directory, recursive: true);
        }
        catch (IOException)
        {
            Thread.Sleep(50);
            Directory.Delete(directory, recursive: true);
        }
    }
}
