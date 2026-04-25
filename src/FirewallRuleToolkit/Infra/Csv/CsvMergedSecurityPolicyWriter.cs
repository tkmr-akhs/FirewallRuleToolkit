using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv;

/// <summary>
/// 統合済みセキュリティ ポリシーを人が読みやすい CSV で書き出します。
/// </summary>
public sealed class CsvMergedSecurityPolicyWriter : IWriteRepository<MergedSecurityPolicy>
{
    private readonly string path;
    private readonly CsvOptions options;
    private readonly AddressGroupCompactor? sourceAddressCompactor;
    private readonly AddressGroupCompactor? destinationAddressCompactor;

    /// <summary>
    /// 統合済みセキュリティ ポリシーを人が読みやすい CSV で書き出しするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">出力先 CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    /// <param name="sourceAddressCompactor">送信元アドレス圧縮器。</param>
    /// <param name="destinationAddressCompactor">宛先アドレス圧縮器。省略時は送信元アドレス圧縮器を使います。</param>
    public CsvMergedSecurityPolicyWriter(
        string path,
        CsvOptions? options = null,
        AddressGroupCompactor? sourceAddressCompactor = null,
        AddressGroupCompactor? destinationAddressCompactor = null)
    {
        this.path = path ?? throw new ArgumentNullException(nameof(path));
        this.options = options ?? new CsvOptions();
        this.sourceAddressCompactor = sourceAddressCompactor;
        this.destinationAddressCompactor = destinationAddressCompactor ?? sourceAddressCompactor;
    }

    /// <summary>
    /// 出力先 CSV を初期化します。
    /// </summary>
    public void Initialize()
    {
        using var writer = CsvRepositoryHelper.CreateWriter(path, options);
        writer.WriteRecord(CsvDatabaseLayout.MergedSecurityPolicies.Headers);
    }

    /// <summary>
    /// 指定された統合済みポリシーを CSV へ追記します。
    /// </summary>
    /// <param name="items">追記するポリシー列。</param>
    public void AppendRange(IEnumerable<MergedSecurityPolicy> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        using var writer = CsvRepositoryHelper.CreateAppendWriter(path, options);
        WritePolicies(writer, items);
    }

    /// <summary>
    /// 指定された統合済みポリシーで CSV を置き換えます。
    /// </summary>
    /// <param name="items">書き出すポリシー列。</param>
    public void ReplaceAll(IEnumerable<MergedSecurityPolicy> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = string.IsNullOrWhiteSpace(directory)
            ? $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp"
            : Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");

        try
        {
            using (var writer = CsvRepositoryHelper.CreateWriter(temporaryPath, options))
            {
                writer.WriteRecord(CsvDatabaseLayout.MergedSecurityPolicies.Headers);
                WritePolicies(writer, items);
            }

            if (File.Exists(path))
            {
                File.Replace(temporaryPath, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, path);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    /// <summary>
    /// 書き込み完了時の後処理を実行します。
    /// </summary>
    public void Complete()
    {
    }

    private void WritePolicies(CsvFileWriter writer, IEnumerable<MergedSecurityPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);

        foreach (var policy in policies)
        {
            writer.WriteRecord(CreateRecord(policy));
        }
    }

    private IList<string> CreateRecord(MergedSecurityPolicy policy)
    {
        return [
            JoinSorted(policy.FromZones),
            FormatAddresses(policy.SourceAddresses, sourceAddressCompactor),
            JoinSorted(policy.ToZones),
            FormatAddresses(policy.DestinationAddresses, destinationAddressCompactor),
            JoinSorted(policy.Applications),
            JoinSorted(policy.Services, FormatServiceValue),
            EntityValueCodec.FormatAction(policy.Action),
            policy.GroupId,
            policy.MinimumIndex.ToString(),
            policy.MaximumIndex.ToString(),
            JoinSorted(policy.OriginalPolicyNames)
        ];
    }

    private static string FormatAddresses(
        IEnumerable<AddressValue> addresses,
        AddressGroupCompactor? compactor)
    {
        if (compactor is null)
        {
            return JoinSorted(addresses, FormatAddressValue);
        }

        var compacted = compactor.Compact(addresses);
        return string.Join(
            ", ",
            compacted.GroupNames
                .OrderBy(static value => value, StringComparer.Ordinal)
                .Concat(compacted.RemainingAddresses
                    .Select(FormatAddressValue)
                    .OrderBy(static value => value, StringComparer.Ordinal)));
    }

    private static string JoinSorted(IEnumerable<string> values)
    {
        return string.Join(", ", values.OrderBy(value => value, StringComparer.Ordinal));
    }

    private static string JoinSorted<T>(IEnumerable<T> values, Func<T, string> formatter)
    {
        return string.Join(", ", values
            .Select(formatter)
            .OrderBy(value => value, StringComparer.Ordinal));
    }

    private static string FormatAddressValue(AddressValue value)
    {
        if (TryFormatCidr(value, out var cidr))
        {
            return cidr;
        }

        return $"{FormatIpv4(value.Start)}-{FormatIpv4(value.Finish)}";
    }

    private static bool TryFormatCidr(AddressValue value, out string cidr)
    {
        cidr = string.Empty;
        if (value.Start > value.Finish)
        {
            return false;
        }

        var rangeSize = (ulong)value.Finish - value.Start + 1UL;
        var isPowerOfTwo = (rangeSize & (rangeSize - 1UL)) == 0UL;
        if (!isPowerOfTwo)
        {
            return false;
        }

        if ((ulong)value.Start % rangeSize != 0UL)
        {
            return false;
        }

        var prefixLength = 32 - GetLog2(rangeSize);
        if (prefixLength == 0)
        {
            cidr = "any";
            return true;
        }

        cidr = $"{FormatIpv4(value.Start)}/{prefixLength}";
        return true;
    }

    private static int GetLog2(ulong value)
    {
        var result = 0;
        while (value > 1UL)
        {
            value >>= 1;
            result++;
        }

        return result;
    }

    private static string FormatIpv4(uint value)
    {
        return $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";
    }

    private static string FormatServiceValue(ServiceValue value)
    {
        if (!string.IsNullOrWhiteSpace(value.Kind))
        {
            return value.Kind;
        }

        if (IsAnyServiceValue(value))
        {
            return "any";
        }

        return $"{FormatProtocol(value.ProtocolStart, value.ProtocolFinish)} {FormatPortRange(value.SourcePortStart, value.SourcePortFinish)} {FormatPortRange(value.DestinationPortStart, value.DestinationPortFinish)}";
    }

    private static bool IsAnyServiceValue(ServiceValue value)
    {
        return value.ProtocolStart == 0U
            && value.ProtocolFinish == 255U
            && value.SourcePortStart == 0U
            && value.SourcePortFinish == 65535U
            && value.DestinationPortStart == 0U
            && value.DestinationPortFinish == 65535U;
    }

    private static string FormatProtocol(uint start, uint finish)
    {
        if (IsAnyProtocolRange(start, finish))
        {
            return "any";
        }

        if (start == finish)
        {
            return GetProtocolName(start);
        }

        return $"{GetProtocolName(start)}-{GetProtocolName(finish)}";
    }

    private static bool IsAnyProtocolRange(uint start, uint finish)
    {
        return start == 0U && (finish == 254U || finish == 255U);
    }

    private static string GetProtocolName(uint protocol)
    {
        return protocol switch
        {
            1U => "icmp",
            6U => "tcp",
            17U => "udp",
            132U => "sctp",
            _ => protocol.ToString()
        };
    }

    private static string FormatPortRange(uint start, uint finish)
    {
        if (IsAnyPortRange(start, finish))
        {
            return "any";
        }

        if (start == finish)
        {
            return start.ToString();
        }

        return $"{start}-{finish}";
    }

    private static bool IsAnyPortRange(uint start, uint finish)
    {
        return start == 0U && finish == 65535U
            || start == 1U && finish == 65535U;
    }
}
