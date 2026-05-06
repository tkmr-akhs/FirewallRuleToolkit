using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Infra.Sqlite;

namespace FirewallRuleToolkit.Composition;

/// <summary>
/// stat ユースケースの具象依存を組み立てます。
/// </summary>
public static class StatComposition
{
    /// <summary>
    /// stat ユースケースを実行します。
    /// </summary>
    public static int Run(string databaseDirectory)
    {
        IItemCountRepository securityPolicies = new SqliteImportedSecurityPolicyRepository(databaseDirectory);
        IItemCountRepository addressDefinitions = new SqliteAddressDefinitionRepository(databaseDirectory);
        IItemCountRepository addressGroups = new SqliteAddressGroupRepository(databaseDirectory);
        IItemCountRepository serviceDefinitions = new SqliteServiceDefinitionRepository(databaseDirectory);
        IItemCountRepository serviceGroups = new SqliteServiceGroupRepository(databaseDirectory);

        IItemCountRepository atomicPolicies = new SqliteAtomicPolicyRepository(databaseDirectory);
        IItemCountRepository mergedPolicies = new SqliteMergedSecurityPolicyRepository(databaseDirectory);

        return StatUseCase.Execute(
            securityPolicies,
            addressDefinitions,
            addressGroups,
            serviceDefinitions,
            serviceGroups,
            atomicPolicies,
            mergedPolicies,
            Console.WriteLine);
    }
}
