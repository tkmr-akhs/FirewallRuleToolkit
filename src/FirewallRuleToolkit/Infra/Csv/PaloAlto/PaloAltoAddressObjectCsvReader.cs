using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv.PaloAlto;

/// <summary>
/// PaloAlto 機器用 アドレス オブジェクト CSV を読み取ります。
/// </summary>
public sealed class PaloAltoAddressObjectCsvReader : IReadRepository<AddressObject>
{
    private readonly string path;
    private readonly CsvOptions options;

    /// <summary>
    /// PaloAlto 機器用 アドレス オブジェクト CSV を読み取りするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    public PaloAltoAddressObjectCsvReader(string path, CsvOptions? options = null)
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
            throw new RepositoryUnavailableException($"Address objects csv is unavailable. path: {path}");
        }
    }

    /// <summary>
    /// アドレス オブジェクトを列挙します。
    /// </summary>
    /// <returns>アドレス オブジェクトの列挙。</returns>
    public IEnumerable<AddressObject> GetAll()
    {
        foreach (var row in CsvRepositoryHelper.ReadRowsWithRecordNumbers(path, options))
        {
            AddressObject addressObject;
            try
            {
                addressObject = CreateAddressObject(row.Values);
            }
            catch (Exception ex) when (CsvRepositoryHelper.IsReadExceptionCause(ex))
            {
                throw CsvRepositoryHelper.CreateReadException(path, row.RecordNumber, ex);
            }

            yield return addressObject;
        }
    }

    private static AddressObject CreateAddressObject(IReadOnlyDictionary<string, string> row)
    {
        return new AddressObject
        {
            Name = CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoAddressObjects.NameHeader),
            Value = NormalizeAddressValue(CsvRepositoryHelper.GetRequiredValue(row, CsvDatabaseLayout.PaloAltoAddressObjects.AddressHeader))
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

