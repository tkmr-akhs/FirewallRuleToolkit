using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv.PaloAlto;

/// <summary>
/// PaloAlto 機器用セキュリティ ポリシー CSV を読み取ります。
/// </summary>
public sealed class PaloAltoSecurityPolicyCsvReader : IReadRepository<ImportedSecurityPolicy>
{
    private readonly string path;
    private readonly CsvOptions options;

    /// <summary>
    /// PaloAlto 機器用セキュリティ ポリシー CSV を読み取りするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    public PaloAltoSecurityPolicyCsvReader(string path, CsvOptions? options = null)
    {
        this.path = path ?? throw new ArgumentNullException(nameof(path));
        this.options = options ?? new CsvOptions();
    }

    /// <summary>
    /// リポジトリが読み取り可能な状態かを確認します。
    /// </summary>
    public void EnsureAvailable()
    {
        if (!File.Exists(path))
        {
            throw new RepositoryUnavailableException($"Security policies csv is unavailable. path: {path}");
        }
    }

    /// <summary>
    /// セキュリティ ポリシーを列挙します。
    /// </summary>
    /// <returns>未解決セキュリティ ポリシーの列挙。</returns>
    public IEnumerable<ImportedSecurityPolicy> GetAll()
    {
        foreach (var row in CsvRepositoryHelper.ReadRowsWithRecordNumbers(path, options))
        {
            ImportedSecurityPolicy securityPolicy;
            try
            {
                securityPolicy = CreateSecurityPolicy(row.Values);
            }
            catch (Exception ex) when (CsvRepositoryHelper.IsReadExceptionCause(ex))
            {
                throw CsvRepositoryHelper.CreateReadException(path, row.RecordNumber, ex);
            }

            yield return securityPolicy;
        }
    }

    private static ImportedSecurityPolicy CreateSecurityPolicy(IReadOnlyDictionary<string, string> row)
    {
        row.TryGetValue(CsvDatabaseLayout.PaloAltoSecurityPolicies.RuleUsageContentHeader, out var ruleUsageContent);

        return new ImportedSecurityPolicy
        {
            Index = EntityValueCodec.ParsePolicyIndex(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoSecurityPolicies.IndexHeader)),
            Name = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoSecurityPolicies.NameHeader),
            FromZones = SplitMultiValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoSecurityPolicies.FromZoneHeader)).ToArray(),
            SourceAddressReferences = SplitMultiValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoSecurityPolicies.SourceAddressHeader)).ToArray(),
            ToZones = SplitMultiValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoSecurityPolicies.ToZoneHeader)).ToArray(),
            DestinationAddressReferences = SplitMultiValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoSecurityPolicies.DestinationAddressHeader)).ToArray(),
            Applications = SplitMultiValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoSecurityPolicies.ApplicationHeader)).ToArray(),
            ServiceReferences = SplitMultiValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoSecurityPolicies.ServiceHeader)).ToArray(),
            Action = EntityValueCodec.ParseAction(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoSecurityPolicies.ActionHeader)),
            GroupId = ParseGroupIdFromRuleUsageContent(ruleUsageContent ?? string.Empty)
        };
    }

    private static string ParseGroupIdFromRuleUsageContent(string value)
    {
        var trimmed = value.Trim();
        var separatorIndex = trimmed.IndexOf('|');
        if (separatorIndex < 0)
        {
            return string.Empty;
        }

        return trimmed[..separatorIndex].Trim();
    }

    private static IEnumerable<string> SplitMultiValue(string value)
    {
        foreach (var item in value.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            yield return item;
        }
    }
}

