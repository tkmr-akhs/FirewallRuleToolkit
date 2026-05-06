namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// 複数 repository への書き込みを 1 つの作業単位として扱います。
/// </summary>
public interface IWriteRepositorySession : IDisposable
{
    /// <summary>
    /// 名前付きアドレス定義 repository を取得します。
    /// </summary>
    IReadWriteRepository<AddressDefinition> AddressDefinitions { get; }

    /// <summary>
    /// アドレス グループ repository を取得します。
    /// </summary>
    IReadWriteRepository<AddressGroupMembership> AddressGroups { get; }

    /// <summary>
    /// 名前付きサービス定義 repository を取得します。
    /// </summary>
    IReadWriteRepository<ServiceDefinition> ServiceDefinitions { get; }

    /// <summary>
    /// サービス グループ repository を取得します。
    /// </summary>
    IReadWriteRepository<ServiceGroupMembership> ServiceGroups { get; }

    /// <summary>
    /// import 済みセキュリティ ポリシー repository を取得します。
    /// </summary>
    IWriteRepository<ImportedSecurityPolicy> ImportedSecurityPolicies { get; }

    /// <summary>
    /// 原子的なセキュリティ ポリシー repository を取得します。
    /// </summary>
    IReadWriteRepository<AtomicSecurityPolicy> AtomicPolicies { get; }

    /// <summary>
    /// 統合済みセキュリティ ポリシー repository を取得します。
    /// </summary>
    IReadWriteRepository<MergedSecurityPolicy> MergedSecurityPolicies { get; }

    /// <summary>
    /// ツール実行メタデータ repository を取得します。
    /// </summary>
    IToolMetadataRepository ToolMetadata { get; }

    /// <summary>
    /// セッション内の書き込みを確定します。
    /// </summary>
    void Commit();
}
