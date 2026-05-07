using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv.PaloAlto;

/// <summary>
/// PaloAlto 機器用サービス定義 CSV を読み取ります。
/// </summary>
public sealed class PaloAltoServiceDefinitionCsvReader : IReadRepository<ServiceDefinition>
{
    private readonly string path;
    private readonly CsvOptions options;

    /// <summary>
    /// PaloAlto 機器用サービス定義 CSV を読み取りするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    public PaloAltoServiceDefinitionCsvReader(string path, CsvOptions? options = null)
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
            throw new RepositoryUnavailableException($"Service definitions csv is unavailable. path: {path}");
        }
    }

    /// <summary>
    /// 名前付きサービス定義を列挙します。
    /// </summary>
    /// <returns>名前付きサービス定義の列挙。</returns>
    public IEnumerable<ServiceDefinition> GetAll()
    {
        foreach (var row in CsvRepositoryHelper.ReadRowsWithRecordNumbers(path, options))
        {
            ServiceDefinition serviceDefinition;
            try
            {
                serviceDefinition = CreateServiceDefinition(row.Values);
            }
            catch (Exception ex) when (CsvRepositoryHelper.IsReadExceptionCause(ex))
            {
                throw CsvRepositoryHelper.CreateReadException(path, row.RecordNumber, ex);
            }

            yield return serviceDefinition;
        }
    }

    private static ServiceDefinition CreateServiceDefinition(IReadOnlyDictionary<string, string> row)
    {
        return new ServiceDefinition
        {
            Name = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoServiceDefinitions.NameHeader),
            Protocol = PaloAltoServiceValueNormalizer.NormalizeDefinitionProtocol(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoServiceDefinitions.ProtocolHeader)),
            SourcePort = PaloAltoServiceValueNormalizer.NormalizeDefinitionPortValue(GetRequiredOrDefault(row, CsvDatabaseLayout.PaloAltoServiceDefinitions.SourcePortHeader, "any")),
            DestinationPort = PaloAltoServiceValueNormalizer.NormalizeDefinitionPortValue(GetRequiredOrDefault(row, CsvDatabaseLayout.PaloAltoServiceDefinitions.DestinationPortHeader, "any")),
            Kind = null
        };
    }

    private static string GetRequiredOrDefault(IReadOnlyDictionary<string, string> row, string headerName, string defaultValue)
    {
        return row.TryGetValue(headerName, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : defaultValue;
    }
}
