using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Infra.Sqlite;

namespace FirewallRuleToolkit.App.Composition;

/// <summary>
/// test ユースケースの具象依存を組み立てます。
/// </summary>
internal static class TestComposition
{
    /// <summary>
    /// test ユースケースを実行します。
    /// </summary>
    public static int Run(string databaseDirectory)
    {
        var atomicPolicies = new SqliteAtomicPolicyRepository(databaseDirectory);
        IReadRepository<MergedSecurityPolicy> mergedPolicies = new SqliteMergedSecurityPolicyRepository(databaseDirectory);

        CompositionRepositoryHelper.EnsureAvailableOrThrow(
            atomicPolicies.EnsureAvailable,
            static _ => new ApplicationUsageException("Atomize has not been executed. Please run atomize first."));
        CompositionRepositoryHelper.EnsureAvailableOrThrow(
            mergedPolicies.EnsureAvailable,
            static _ => new ApplicationUsageException("Merge has not been executed. Please run merge first."));

        return TestUseCase.Execute(
            atomicPolicies,
            mergedPolicies);
    }
}
