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
        AddressDefinitions = new SqliteAddressDefinitionRepository(transaction);
        AddressGroups = new SqliteAddressGroupRepository(transaction);
        ServiceDefinitions = new SqliteServiceDefinitionRepository(transaction);
        ServiceGroups = new SqliteServiceGroupRepository(transaction);
        ImportedSecurityPolicies = new SqliteImportedSecurityPolicyRepository(transaction);
        AtomicPolicies = new SqliteAtomicPolicyRepository(transaction);
        MergedSecurityPolicies = new SqliteMergedSecurityPolicyRepository(transaction);
        ToolMetadata = new SqliteToolMetadataRepository(transaction);
    }

    public IReadWriteRepository<AddressDefinition> AddressDefinitions { get; }

    public IReadWriteRepository<AddressGroupMembership> AddressGroups { get; }

    public IReadWriteRepository<ServiceDefinition> ServiceDefinitions { get; }

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
