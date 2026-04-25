namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// SQLite トランザクションに束ねられた repository セッションです。
/// </summary>
internal sealed class SqliteRepositorySession : IWriteRepositorySession
{
    private readonly SqliteWriteTransaction transaction;

    public SqliteRepositorySession(SqliteWriteTransaction transaction)
    {
        this.transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));
        AddressObjects = new SqliteAddressObjectRepository(transaction);
        AddressGroups = new SqliteAddressGroupRepository(transaction);
        ServiceObjects = new SqliteServiceObjectRepository(transaction);
        ServiceGroups = new SqliteServiceGroupRepository(transaction);
        ImportedSecurityPolicies = new SqliteImportedSecurityPolicyRepository(transaction);
        AtomicPolicies = new SqliteAtomicPolicyRepository(transaction);
        MergedSecurityPolicies = new SqliteMergedSecurityPolicyRepository(transaction);
        ToolMetadata = new SqliteToolMetadataRepository(transaction);
    }

    public IReadWriteRepository<AddressObject> AddressObjects { get; }

    public IReadWriteRepository<AddressGroupMembership> AddressGroups { get; }

    public IReadWriteRepository<ServiceObject> ServiceObjects { get; }

    public IReadWriteRepository<ServiceGroupMembership> ServiceGroups { get; }

    public IWriteRepository<ImportedSecurityPolicy> ImportedSecurityPolicies { get; }

    public IReadWriteRepository<AtomicSecurityPolicy> AtomicPolicies { get; }

    public IReadWriteRepository<MergedSecurityPolicy> MergedSecurityPolicies { get; }

    public IToolMetadataRepository ToolMetadata { get; }

    public void Commit()
    {
        transaction.Commit();
    }

    public void Dispose()
    {
        transaction.Dispose();
    }
}
