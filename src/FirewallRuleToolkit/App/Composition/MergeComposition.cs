using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Infra.Sqlite;

namespace FirewallRuleToolkit.App.Composition;

/// <summary>
/// merge ユースケースの構成を組み立てます。
/// </summary>
internal static class MergeComposition
{
    /// <summary>
    /// merge ユースケースを実行します。
    /// </summary>
    public static int Run(
        string databaseDirectory,
        uint highSimilarityPercentThreshold,
        IReadOnlySet<uint>? wellKnownDestinationPorts = null,
        uint? smallWellKnownDestinationPortCountThreshold = null)
    {
        var sourceAtomicPolicies = new SqliteAtomicPolicyRepository(databaseDirectory);

        try
        {
            sourceAtomicPolicies.EnsureAvailable();
            IWriteRepositorySessionFactory writeSessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);
            using var writeSession = writeSessionFactory.BeginWriteSession();

            return MergeUseCase.Execute(
                sourceAtomicPolicies,
                writeSession,
                highSimilarityPercentThreshold,
                wellKnownDestinationPorts: wellKnownDestinationPorts,
                smallWellKnownDestinationPortCountThreshold: smallWellKnownDestinationPortCountThreshold);
        }
        catch (RepositoryUnavailableException)
        {
            throw new ApplicationUsageException("Atomize has not been executed. Please run atomize first.");
        }
    }
}
