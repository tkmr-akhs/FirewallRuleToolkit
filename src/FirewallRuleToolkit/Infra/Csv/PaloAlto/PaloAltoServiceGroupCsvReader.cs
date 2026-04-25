using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv.PaloAlto;

/// <summary>
/// PaloAlto 機器用 サービス グループ CSV を読み取ります。
/// </summary>
public sealed class PaloAltoServiceGroupCsvReader : IReadRepository<ServiceGroupMembership>
{
    private readonly string path;
    private readonly CsvOptions options;

    /// <summary>
    /// PaloAlto 機器用 サービス グループ CSV を読み取りするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    public PaloAltoServiceGroupCsvReader(string path, CsvOptions? options = null)
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
            throw new RepositoryUnavailableException($"Service groups csv is unavailable. path: {path}");
        }
    }

    /// <summary>
    /// サービス グループ メンバーを列挙します。
    /// </summary>
    /// <returns>サービス グループ メンバーの列挙。</returns>
    public IEnumerable<ServiceGroupMembership> GetAll()
    {
        foreach (var row in CsvRepositoryHelper.ReadRowsWithRecordNumbers(path, options))
        {
            ServiceGroupMembership[] memberships;
            try
            {
                memberships = CreateMemberships(row.Values).ToArray();
            }
            catch (Exception ex) when (CsvRepositoryHelper.IsReadExceptionCause(ex))
            {
                throw CsvRepositoryHelper.CreateReadException(path, row.RecordNumber, ex);
            }

            foreach (var membership in memberships)
            {
                yield return membership;
            }
        }
    }

    private static IEnumerable<ServiceGroupMembership> CreateMemberships(IReadOnlyDictionary<string, string> row)
    {
        var groupName = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoServiceGroups.NameHeader);

        foreach (var memberName in SplitMultiValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoServiceGroups.ServiceHeader)))
        {
            yield return new ServiceGroupMembership
            {
                GroupName = groupName,
                MemberName = memberName
            };
        }
    }

    private static IEnumerable<string> SplitMultiValue(string value)
    {
        foreach (var item in value.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            yield return item;
        }
    }
}

