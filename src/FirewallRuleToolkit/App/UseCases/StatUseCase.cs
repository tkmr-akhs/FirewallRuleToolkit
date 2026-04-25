using FirewallRuleToolkit.Domain;

namespace FirewallRuleToolkit.App.UseCases;

/// <summary>
/// stat サブコマンドの処理を提供します。
/// </summary>
internal static class StatUseCase
{
    public readonly record struct ImportedTableCounts(
        int SecurityPolicies,
        int AddressObjects,
        int AddressGroupMembers,
        int ServiceObjects,
        int ServiceGroupMembers);

    /// <summary>
    /// データベースの統計情報を出力します。
    /// </summary>
    /// <param name="securityPolicies">import 済みセキュリティ ポリシー件数 repository。</param>
    /// <param name="addressObjects">アドレス オブジェクト件数 repository。</param>
    /// <param name="addressGroups">アドレス グループ件数 repository。</param>
    /// <param name="serviceObjects">サービス オブジェクト件数 repository。</param>
    /// <param name="serviceGroups">サービス グループ件数 repository。</param>
    /// <param name="atomicPolicies">Atomic ポリシー件数 repository。</param>
    /// <param name="mergedPolicies">Merged ポリシー件数 repository。</param>
    /// <param name="writeLine">1 行出力関数。</param>
    /// <returns>終了コード。</returns>
    public static int Execute(
        IItemCountRepository securityPolicies,
        IItemCountRepository addressObjects,
        IItemCountRepository addressGroups,
        IItemCountRepository serviceObjects,
        IItemCountRepository serviceGroups,
        IItemCountRepository atomicPolicies,
        IItemCountRepository mergedPolicies,
        Action<string> writeLine)
    {
        ArgumentNullException.ThrowIfNull(securityPolicies);
        ArgumentNullException.ThrowIfNull(addressObjects);
        ArgumentNullException.ThrowIfNull(addressGroups);
        ArgumentNullException.ThrowIfNull(serviceObjects);
        ArgumentNullException.ThrowIfNull(serviceGroups);
        ArgumentNullException.ThrowIfNull(atomicPolicies);
        ArgumentNullException.ThrowIfNull(mergedPolicies);
        ArgumentNullException.ThrowIfNull(writeLine);

        writeLine(string.Empty);

        try
        {
            var imported = GetImportedCounts(
                securityPolicies,
                addressObjects,
                addressGroups,
                serviceObjects,
                serviceGroups);

            writeLine("Import: completed");
            writeLine($"security_policies: {imported.SecurityPolicies}");
            writeLine($"address_objects: {imported.AddressObjects}");
            writeLine($"address_group_members: {imported.AddressGroupMembers}");
            writeLine($"service_objects: {imported.ServiceObjects}");
            writeLine($"service_group_members: {imported.ServiceGroupMembers}");
            writeLine(string.Empty);
        }
        catch (RepositoryUnavailableException)
        {
            writeLine("Import: not imported");
        }

        try
        {
            var atomicCount = CountAvailableItems(atomicPolicies);
            writeLine("Atomize: completed");
            writeLine($"atomic_security_policies: {atomicCount}");
            writeLine(string.Empty);
        }
        catch (RepositoryUnavailableException)
        {
            writeLine("Atomize: not atomized");
        }

        try
        {
            var mergedCount = CountAvailableItems(mergedPolicies);
            writeLine("Merge: completed");
            writeLine($"merged_security_policies: {mergedCount}");
        }
        catch (RepositoryUnavailableException)
        {
            writeLine("Merge: not merged");
        }

        writeLine(string.Empty);

        return 0;
    }

    private static ImportedTableCounts GetImportedCounts(
        IItemCountRepository securityPolicies,
        IItemCountRepository addressObjects,
        IItemCountRepository addressGroups,
        IItemCountRepository serviceObjects,
        IItemCountRepository serviceGroups)
    {
        securityPolicies.EnsureAvailable();
        addressObjects.EnsureAvailable();
        addressGroups.EnsureAvailable();
        serviceObjects.EnsureAvailable();
        serviceGroups.EnsureAvailable();

        return new ImportedTableCounts(
            securityPolicies.Count(),
            addressObjects.Count(),
            addressGroups.Count(),
            serviceObjects.Count(),
            serviceGroups.Count());
    }

    private static int CountAvailableItems(IItemCountRepository repository)
    {
        repository.EnsureAvailable();
        return repository.Count();
    }
}
