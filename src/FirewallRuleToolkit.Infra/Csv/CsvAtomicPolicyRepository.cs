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
                SourceAddress = new AddressValue
                {
                    Start = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.SourceAddressStartHeader),
                    Finish = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.SourceAddressFinishHeader)
                },
                ToZone = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.ToZoneHeader),
                DestinationAddress = new AddressValue
                {
                    Start = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.DestinationAddressStartHeader),
                    Finish = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.DestinationAddressFinishHeader)
                },
                Application = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.ApplicationHeader),
                Service = new ServiceValue
                {
                    ProtocolStart = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.ServiceProtocolStartHeader),
                    ProtocolFinish = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.ServiceProtocolFinishHeader),
                    SourcePortStart = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.ServiceSourcePortStartHeader),
                    SourcePortFinish = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.ServiceSourcePortFinishHeader),
                    DestinationPortStart = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.ServiceDestinationPortStartHeader),
                    DestinationPortFinish = GetRequiredUInt32(row, CsvDatabaseLayout.AtomicSecurityPolicies.ServiceDestinationPortFinishHeader),
                    Kind = GetOptionalValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.ServiceKindHeader)
                },
                Action = EntityValueCodec.ParseAction(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.ActionHeader)),
                GroupId = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.GroupIdHeader),
                OriginalIndex = EntityValueCodec.ParsePolicyIndex(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.OriginalIndexHeader)),
                OriginalPolicyName = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.AtomicSecurityPolicies.OriginalPolicyNameHeader)
            },
            static atomicPolicy => [
                atomicPolicy.FromZone,
                atomicPolicy.SourceAddress.Start.ToString(),
                atomicPolicy.SourceAddress.Finish.ToString(),
                atomicPolicy.ToZone,
                atomicPolicy.DestinationAddress.Start.ToString(),
                atomicPolicy.DestinationAddress.Finish.ToString(),
                atomicPolicy.Application,
                atomicPolicy.Service.ProtocolStart.ToString(),
                atomicPolicy.Service.ProtocolFinish.ToString(),
                atomicPolicy.Service.SourcePortStart.ToString(),
                atomicPolicy.Service.SourcePortFinish.ToString(),
                atomicPolicy.Service.DestinationPortStart.ToString(),
                atomicPolicy.Service.DestinationPortFinish.ToString(),
                atomicPolicy.Service.Kind ?? string.Empty,
                EntityValueCodec.FormatAction(atomicPolicy.Action),
                atomicPolicy.GroupId,
                atomicPolicy.OriginalIndex.ToString(),
                atomicPolicy.OriginalPolicyName
            ])
    {
    }

    private static uint GetRequiredUInt32(IReadOnlyDictionary<string, string> row, string headerName)
    {
        return uint.Parse(CsvRepositoryHelper.GetRequiredValue(row, headerName));
    }

    private static string? GetOptionalValue(IReadOnlyDictionary<string, string> row, string headerName)
    {
        return row.TryGetValue(headerName, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;
    }
}

