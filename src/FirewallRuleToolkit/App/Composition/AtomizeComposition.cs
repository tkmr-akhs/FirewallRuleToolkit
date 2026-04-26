using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Infra.Sqlite;

namespace FirewallRuleToolkit.App.Composition;

/// <summary>
/// atomize ユースケースの構成を組み立てます。
/// </summary>
internal static class AtomizeComposition
{
    /// <summary>
    /// atomize ユースケースを実行します。
    /// </summary>
    public static int Run(string databaseDirectory, int threshold)
    {
        IReadRepository<ImportedSecurityPolicy> sourceSecurityPolicies = new SqliteImportedSecurityPolicyRepository(databaseDirectory);
        var addressDefinitionSource = new SqliteAddressDefinitionRepository(databaseDirectory);
        var addressGroupSource = new SqliteAddressGroupRepository(databaseDirectory);
        var serviceDefinitionSource = new SqliteServiceDefinitionRepository(databaseDirectory);
        var serviceGroupSource = new SqliteServiceGroupRepository(databaseDirectory);
        IWriteRepositorySessionFactory writeSessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);

        return CompositionRepositoryHelper.ExecuteWhenAvailable(
            () =>
            {
                var addressResolver = new AddressReferenceResolver(
                    LookupRepositoryFactory.CreateAddressDefinitionLookup(addressDefinitionSource),
                    LookupRepositoryFactory.CreateAddressGroupLookup(addressGroupSource));
                var serviceResolver = new ServiceReferenceResolver(
                    LookupRepositoryFactory.CreateServiceDefinitionLookup(serviceDefinitionSource),
                    LookupRepositoryFactory.CreateServiceGroupLookup(serviceGroupSource));
                var securityPolicyResolver = new SecurityPolicyResolver(addressResolver, serviceResolver);

                using var writeSession = writeSessionFactory.BeginWriteSession();

                var exitCode = AtomizeUseCase.Execute(
                    threshold,
                    securityPolicyResolver,
                    sourceSecurityPolicies,
                    writeSession);
                return exitCode;
            },
            static _ => new ApplicationUsageException("Import has not been executed. Please run import first."),
            sourceSecurityPolicies.EnsureAvailable,
            addressDefinitionSource.EnsureAvailable,
            addressGroupSource.EnsureAvailable,
            serviceDefinitionSource.EnsureAvailable,
            serviceGroupSource.EnsureAvailable);
    }

}
