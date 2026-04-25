using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv.PaloAlto;

/// <summary>
/// PaloAlto 機器用 サービス オブジェクト CSV を読み取ります。
/// </summary>
public sealed class PaloAltoServiceObjectCsvReader : IReadRepository<ServiceObject>
{
    private readonly string path;
    private readonly CsvOptions options;

    /// <summary>
    /// PaloAlto 機器用 サービス オブジェクト CSV を読み取りするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    public PaloAltoServiceObjectCsvReader(string path, CsvOptions? options = null)
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
            throw new RepositoryUnavailableException($"Service objects csv is unavailable. path: {path}");
        }
    }

    /// <summary>
    /// サービス オブジェクトを列挙します。
    /// </summary>
    /// <returns>サービス オブジェクトの列挙。</returns>
    public IEnumerable<ServiceObject> GetAll()
    {
        foreach (var row in CsvRepositoryHelper.ReadRowsWithRecordNumbers(path, options))
        {
            ServiceObject serviceObject;
            try
            {
                serviceObject = CreateServiceObject(row.Values);
            }
            catch (Exception ex) when (CsvRepositoryHelper.IsReadExceptionCause(ex))
            {
                throw CsvRepositoryHelper.CreateReadException(path, row.RecordNumber, ex);
            }

            yield return serviceObject;
        }
    }

    private static ServiceObject CreateServiceObject(IReadOnlyDictionary<string, string> row)
    {
        return new ServiceObject
        {
            Name = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoServiceObjects.NameHeader),
            Protocol = NormalizeProtocol(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoServiceObjects.ProtocolHeader)),
            SourcePort = NormalizePortValue(GetRequiredOrDefault(row, CsvDatabaseLayout.PaloAltoServiceObjects.SourcePortHeader, "any")),
            DestinationPort = NormalizePortValue(GetRequiredOrDefault(row, CsvDatabaseLayout.PaloAltoServiceObjects.DestinationPortHeader, "any")),
            Kind = null
        };
    }

    private static string GetRequiredOrDefault(IReadOnlyDictionary<string, string> row, string headerName, string defaultValue)
    {
        return row.TryGetValue(headerName, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : defaultValue;
    }

    private static string NormalizeProtocol(string protocol)
    {
        return protocol.Trim().ToUpperInvariant() switch
        {
            "TCP" => "6",
            "UDP" => "17",
            "ICMP" => "1",
            "SCTP" => "132",
            _ => protocol.Trim()
        };
    }

    private static string NormalizePortValue(string port)
    {
        var trimmed = port.Trim();
        var items = trimmed
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(NormalizePortItem)
            .ToArray();

        if (items.Length == 0)
        {
            throw new FormatException("Port value is required.");
        }

        return string.Join(",", items);
    }

    private static string NormalizePortItem(string port)
    {
        if (port.Equals("any", StringComparison.OrdinalIgnoreCase))
        {
            return "1-65535";
        }

        if (port.Equals("0", StringComparison.Ordinal))
        {
            return "1";
        }

        if (!port.StartsWith("0-", StringComparison.Ordinal))
        {
            return port;
        }

        var finish = port[2..];
        return finish.Equals("0", StringComparison.Ordinal)
            ? "1"
            : $"1-{finish}";
    }
}
