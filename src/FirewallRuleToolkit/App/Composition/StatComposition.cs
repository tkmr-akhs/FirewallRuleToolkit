using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Infra.Sqlite;

namespace FirewallRuleToolkit.App.Composition;

/// <summary>
/// stat ユースケースの具象依存を組み立てます。
/// </summary>
internal static class StatComposition
{
    /// <summary>
    /// stat ユースケースを実行します。
    /// </summary>
    public static int Run(string databaseDirectory)
    {
        IItemCountRepository securityPolicies = new SqliteImportedSecurityPolicyRepository(databaseDirectory);
        IItemCountRepository addressObjects = new SqliteAddressObjectRepository(databaseDirectory);
        IItemCountRepository addressGroups = new SqliteAddressGroupRepository(databaseDirectory);
        IItemCountRepository serviceObjects = new SqliteServiceObjectRepository(databaseDirectory);
        IItemCountRepository serviceGroups = new SqliteServiceGroupRepository(databaseDirectory);

        IItemCountRepository atomicPolicies = new SqliteAtomicPolicyRepository(databaseDirectory);
        IItemCountRepository mergedPolicies = new SqliteMergedSecurityPolicyRepository(databaseDirectory);

        return StatUseCase.Execute(
            securityPolicies,
            addressObjects,
            addressGroups,
            serviceObjects,
            serviceGroups,
            atomicPolicies,
            mergedPolicies,
            Console.WriteLine);
    }
}
