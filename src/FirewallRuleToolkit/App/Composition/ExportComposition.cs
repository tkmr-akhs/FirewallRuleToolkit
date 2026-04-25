using System.Text;
using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Config;
using FirewallRuleToolkit.Infra.Csv;
using FirewallRuleToolkit.Infra.Csv.Lib;
using FirewallRuleToolkit.Infra.Sqlite;

namespace FirewallRuleToolkit.App.Composition;

/// <summary>
/// export ユースケースの具象依存を組み立てます。
/// </summary>
internal static class ExportComposition
{
    /// <summary>
    /// export ユースケースを実行します。
    /// </summary>
    public static int Run(
        string databaseDirectory,
        Encoding encoding,
        ExportTarget target,
        string? atomicPath,
        string? mergedPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databaseDirectory);
        ArgumentNullException.ThrowIfNull(encoding);

        var csvOptions = new CsvOptions
        {
            Encoding = encoding,
            HasByteOrderMarks = encoding.GetPreamble().Length > 0
        };

        IReadRepository<AtomicSecurityPolicy>? atomicSource = null;
        IWriteRepository<AtomicSecurityPolicy>? atomicDestination = null;
        if (atomicPath is not null)
        {
            atomicSource = new SqliteAtomicPolicyRepository(databaseDirectory);
            atomicDestination = new CsvAtomicPolicyRepository(atomicPath, csvOptions);
        }

        IReadRepository<MergedSecurityPolicy>? mergedSource = null;
        IWriteRepository<MergedSecurityPolicy>? mergedDestination = null;
        if (mergedPath is not null)
        {
            mergedSource = new SqliteMergedSecurityPolicyRepository(databaseDirectory);
            mergedDestination = new CsvMergedSecurityPolicyWriter(
                mergedPath,
                csvOptions,
                CreateAddressGroupCompactor(databaseDirectory));
        }

        return ExportUseCase.Execute(
            target,
            atomicSource,
            atomicDestination,
            mergedSource,
            mergedDestination);
    }

    private static AddressGroupCompactor CreateAddressGroupCompactor(string databaseDirectory)
    {
        var addressObjects = new SqliteAddressObjectRepository(databaseDirectory);
        var addressGroups = new SqliteAddressGroupRepository(databaseDirectory);
        var toolMetadata = new SqliteToolMetadataRepository(databaseDirectory);

        CompositionRepositoryHelper.EnsureAvailableOrThrow(
            addressObjects.EnsureAvailable,
            static _ => new ApplicationUsageException("Import has not been executed. Please run import first."));
        CompositionRepositoryHelper.EnsureAvailableOrThrow(
            addressGroups.EnsureAvailable,
            static _ => new ApplicationUsageException("Import has not been executed. Please run import first."));
        CompositionRepositoryHelper.EnsureAvailableOrThrow(
            toolMetadata.EnsureAvailable,
            static _ => new ApplicationUsageException("Atomize has not been executed. Please run atomize first."));

        if (!toolMetadata.TryGetAtomizeThreshold(out var atomizeThreshold))
        {
            throw new ApplicationUsageException("Atomize has not been executed. Please run atomize first.");
        }

        return new AddressGroupCompactor(
            addressGroups,
            LookupRepositoryFactory.CreateAddressObjectLookup(addressObjects),
            LookupRepositoryFactory.CreateAddressGroupLookup(addressGroups),
            atomizeThreshold);
    }
}
