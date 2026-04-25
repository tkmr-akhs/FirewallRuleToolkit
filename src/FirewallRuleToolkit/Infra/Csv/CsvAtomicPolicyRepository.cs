using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv;

/// <summary>
/// 原子的なセキュリティ ポリシーを CSV で読み書きします。
/// </summary>
public sealed class CsvAtomicPolicyRepository : CsvReadWriteRepositoryBase<AtomicSecurityPolicy>
{
    /// <summary>
    /// 原子的なセキュリティ ポリシーを CSV で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    public CsvAtomicPolicyRepository(string path, CsvOptions? options = null)
        : base(
            path,
            options ?? new CsvOptions(),
            CsvDatabaseLayout.AtomicSecurityPolicies.Headers,
            static row => new AtomicSecurityPolicy
            {
                FromZone = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.FromZoneHeader),
                SourceAddress = EntityValueCodec.DeserializeAddressValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.SourceAddressJsonHeader)),
                ToZone = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.ToZoneHeader),
                DestinationAddress = EntityValueCodec.DeserializeAddressValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.DestinationAddressJsonHeader)),
                Application = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.ApplicationHeader),
                Service = EntityValueCodec.DeserializeServiceValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.ServiceJsonHeader)),
                Action = EntityValueCodec.ParseAction(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.ActionHeader)),
                GroupId = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.GroupIdHeader),
                OriginalIndex = ulong.Parse(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.OriginalIndexHeader)),
                OriginalPolicyName = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.OriginalPolicyNameHeader)
            },
            static atomicPolicy => [
                atomicPolicy.FromZone,
                EntityValueCodec.SerializeAddressValue(atomicPolicy.SourceAddress),
                atomicPolicy.ToZone,
                EntityValueCodec.SerializeAddressValue(atomicPolicy.DestinationAddress),
                atomicPolicy.Application,
                EntityValueCodec.SerializeServiceValue(atomicPolicy.Service),
                EntityValueCodec.FormatAction(atomicPolicy.Action),
                atomicPolicy.GroupId,
                atomicPolicy.OriginalIndex.ToString(),
                atomicPolicy.OriginalPolicyName
            ])
    {
    }
}

