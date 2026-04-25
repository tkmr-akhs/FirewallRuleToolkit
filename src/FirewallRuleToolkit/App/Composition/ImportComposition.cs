using System.Text;
using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Infra.Csv.Lib;
using FirewallRuleToolkit.Infra.Csv.PaloAlto;
using FirewallRuleToolkit.Infra.Sqlite;

namespace FirewallRuleToolkit.App.Composition;

/// <summary>
/// import ユースケースの具象依存を組み立てます。
/// </summary>
internal static class ImportComposition
{
    /// <summary>
    /// import ユースケースを実行します。
    /// </summary>
    public static int Run(
        string databaseDirectory,
        Encoding encoding,
        string securityPoliciesPath,
        string addressesPath,
        string addressGroupsPath,
        string servicesPath,
        string serviceGroupsPath)
    {
        var csvOptions = new CsvOptions
        {
            Encoding = encoding,
            HasByteOrderMarks = encoding.GetPreamble().Length > 0
        };
        IReadRepository<AddressObject> addressObjectReader = new PaloAltoAddressObjectCsvReader(addressesPath, csvOptions);
        IReadRepository<AddressGroupMembership> addressGroupReader = new PaloAltoAddressGroupCsvReader(addressGroupsPath, csvOptions);
        IReadRepository<ServiceObject> serviceObjectReader = new PaloAltoServiceObjectCsvReader(servicesPath, csvOptions);
        IReadRepository<ServiceGroupMembership> serviceGroupReader = new PaloAltoServiceGroupCsvReader(serviceGroupsPath, csvOptions);
        IReadRepository<ImportedSecurityPolicy> securityPolicyReader = new PaloAltoSecurityPolicyCsvReader(securityPoliciesPath, csvOptions);

        try
        {
            addressObjectReader.EnsureAvailable();
            addressGroupReader.EnsureAvailable();
            serviceObjectReader.EnsureAvailable();
            serviceGroupReader.EnsureAvailable();
            securityPolicyReader.EnsureAvailable();
        }
        catch (RepositoryUnavailableException ex)
        {
            throw CreateCsvReadApplicationException(ex);
        }

        IWriteRepositorySessionFactory writeSessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);
        using var writeSession = writeSessionFactory.BeginWriteSession();

        try
        {
            return CompositionRepositoryHelper.ExecuteReadOrThrow(
                () => ImportUseCase.Execute(
                    addressObjectReader,
                    addressGroupReader,
                    serviceObjectReader,
                    serviceGroupReader,
                    securityPolicyReader,
                    writeSession),
                static ex => CreateCsvReadApplicationException(ex));
        }
        catch (RepositoryUnavailableException ex)
        {
            throw CreateCsvReadApplicationException(ex);
        }
    }

    private static ApplicationUsageException CreateCsvReadApplicationException(Exception exception)
    {
        return new ApplicationUsageException($"CSV の読み取りに失敗しました。{exception.Message}", exception);
    }
}
