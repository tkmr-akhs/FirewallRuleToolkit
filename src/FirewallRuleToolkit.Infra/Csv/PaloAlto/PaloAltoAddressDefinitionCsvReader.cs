using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv.PaloAlto;

/// <summary>
/// PaloAlto 機器用アドレス定義 CSV を読み取ります。
/// </summary>
public sealed class PaloAltoAddressDefinitionCsvReader : IReadRepository<AddressDefinition>
{
    private readonly string path;
    private readonly CsvOptions options;

    /// <summary>
    /// PaloAlto 機器用アドレス定義 CSV を読み取りするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    public PaloAltoAddressDefinitionCsvReader(string path, CsvOptions? options = null)
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
            throw new RepositoryUnavailableException($"Address definitions csv is unavailable. path: {path}");
        }
    }

    /// <summary>
    /// 名前付きアドレス定義を列挙します。
    /// </summary>
    /// <returns>名前付きアドレス定義の列挙。</returns>
    public IEnumerable<AddressDefinition> GetAll()
    {
        foreach (var row in CsvRepositoryHelper.ReadRowsWithRecordNumbers(path, options))
        {
            AddressDefinition addressDefinition;
            try
            {
                addressDefinition = CreateAddressDefinition(row.Values);
            }
            catch (Exception ex) when (CsvRepositoryHelper.IsReadExceptionCause(ex))
            {
                throw CsvRepositoryHelper.CreateReadException(path, row.RecordNumber, ex);
            }

            yield return addressDefinition;
        }
    }

    private static AddressDefinition CreateAddressDefinition(IReadOnlyDictionary<string, string> row)
    {
        return new AddressDefinition
        {
            Name = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoAddressDefinitions.NameHeader),
            Value = NormalizeAddressValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoAddressDefinitions.AddressHeader))
        };
    }

    private static string NormalizeAddressValue(string value)
    {
        var trimmed = value.Trim();

        if (trimmed.Contains('/', StringComparison.Ordinal))
        {
            return trimmed;
        }

        return TryParseIpv4Address(trimmed, out var hostValue)
            ? $"{FormatIpv4Address(hostValue)}/32"
            : trimmed;
    }

    private static bool TryParseIpv4Address(string value, out uint address)
    {
        address = 0;

        var octets = value.Split('.', StringSplitOptions.TrimEntries);
        if (octets.Length != 4)
        {
            return false;
        }

        for (var index = 0; index < octets.Length; index++)
        {
            if (!byte.TryParse(octets[index], out var octet))
            {
                return false;
            }

            address = (address << 8) | octet;
        }

        return true;
    }

    private static string FormatIpv4Address(uint value)
    {
        return string.Join('.',
            (value >> 24) & 0xff,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff);
    }
}

