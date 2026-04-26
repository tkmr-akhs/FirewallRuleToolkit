using System.Text.Json;
namespace FirewallRuleToolkit.Infra;

/// <summary>
/// インフラ層で利用する値変換を補助します。
/// </summary>
internal static class EntityValueCodec
{
    private const string ActionAllow = "許可";
    private const string ActionDeny = "拒否";
    private const string ActionDrop = "ドロップ";
    private const string ActionResetBoth = "両方のリセット";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// アクションを永続化向け文字列へ変換します。
    /// </summary>
    /// <param name="action">変換するアクション。</param>
    /// <returns>永続化向けの文字列。</returns>
    public static string FormatAction(SecurityPolicyAction action)
    {
        return action.ToString();
    }

    /// <summary>
    /// 永続化された文字列をアクションへ変換します。
    /// </summary>
    /// <param name="value">変換元の文字列。</param>
    /// <returns>変換後のアクション。</returns>
    public static SecurityPolicyAction ParseAction(string value)
    {
        return value.Trim() switch
        {
            ActionAllow => SecurityPolicyAction.Allow,
            ActionDeny => SecurityPolicyAction.Deny,
            ActionDrop => SecurityPolicyAction.Drop,
            ActionResetBoth => SecurityPolicyAction.ResetBoth,
            _ => Enum.Parse<SecurityPolicyAction>(value, ignoreCase: true)
        };
    }

    /// <summary>
    /// 永続化された文字列をポリシー インデックスへ変換します。
    /// </summary>
    /// <param name="value">変換元の文字列。</param>
    /// <returns>変換後のポリシー インデックス。</returns>
    public static uint ParsePolicyIndex(string value)
    {
        return uint.Parse(value);
    }

    /// <summary>
    /// SQLite から読み取った整数値をポリシー インデックスへ変換します。
    /// </summary>
    /// <param name="value">SQLite から読み取った整数値。</param>
    /// <returns>変換後のポリシー インデックス。</returns>
    public static uint ReadPolicyIndex(long value)
    {
        if (value < 0 || value > uint.MaxValue)
        {
            throw new OverflowException($"Policy index is out of UInt32 range: {value}");
        }

        return (uint)value;
    }

    /// <summary>
    /// ポリシー インデックスを SQLite INTEGER として保存できる値へ変換します。
    /// </summary>
    /// <param name="value">変換対象のポリシー インデックス。</param>
    /// <returns>SQLite INTEGER へバインドする値。</returns>
    public static long FormatPolicyIndex(uint value)
    {
        return value;
    }

    /// <summary>
    /// 元ポリシー名集合を JSON 文字列へ変換します。
    /// </summary>
    /// <param name="originalPolicyNames">変換する元ポリシー名集合。</param>
    /// <returns>JSON 文字列。</returns>
    public static string SerializeOriginalPolicyNames(IEnumerable<string> originalPolicyNames)
    {
        ArgumentNullException.ThrowIfNull(originalPolicyNames);

        return JsonSerializer.Serialize(originalPolicyNames.OrderBy(name => name, StringComparer.Ordinal).ToArray());
    }

    /// <summary>
    /// JSON 文字列から元ポリシー名集合を復元します。
    /// </summary>
    /// <param name="value">復元元の JSON 文字列。</param>
    /// <returns>復元した元ポリシー名集合。</returns>
    public static HashSet<string> DeserializeOriginalPolicyNames(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        var items = JsonSerializer.Deserialize<string[]>(value) ?? [];
        return new HashSet<string>(items, StringComparer.Ordinal);
    }

    /// <summary>
    /// 文字列一覧を JSON 文字列へ変換します。
    /// </summary>
    /// <param name="values">変換する文字列一覧。</param>
    /// <returns>JSON 文字列。</returns>
    public static string SerializeStringList(IEnumerable<string> values)
    {
        return JsonSerializer.Serialize(values.ToArray(), JsonOptions);
    }

    /// <summary>
    /// JSON 文字列から文字列一覧を復元します。
    /// </summary>
    /// <param name="value">復元元の JSON 文字列。</param>
    /// <returns>復元した文字列一覧。</returns>
    public static IReadOnlyList<string> DeserializeStringList(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        return JsonSerializer.Deserialize<string[]>(value, JsonOptions) ?? [];
    }

    /// <summary>
    /// アドレス値を JSON 文字列へ変換します。
    /// </summary>
    /// <param name="value">変換するアドレス値。</param>
    /// <returns>JSON 文字列。</returns>
    public static string SerializeAddressValue(AddressValue value)
    {
        var payload = new Dictionary<string, uint>
        {
            ["s"] = value.Start,
            ["f"] = value.Finish
        };

        return JsonSerializer.Serialize(payload, JsonOptions);
    }

    /// <summary>
    /// JSON 文字列からアドレス値を復元します。
    /// </summary>
    /// <param name="value">復元元の JSON 文字列。</param>
    /// <returns>復元したアドレス値。</returns>
    public static AddressValue DeserializeAddressValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException("address_json must not be empty.");
        }

        using var document = JsonDocument.Parse(value);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("address_json must be a JSON object.");
        }

        return new AddressValue
        {
            Start = ReadRequiredUInt32Value(root, "s"),
            Finish = ReadRequiredUInt32Value(root, "f")
        };
    }

    /// <summary>
    /// サービス値を JSON 文字列へ変換します。
    /// </summary>
    /// <param name="value">変換するサービス値。</param>
    /// <returns>JSON 文字列。</returns>
    public static string SerializeServiceValue(ServiceValue value)
    {
        var payload = new Dictionary<string, object?>
        {
            ["ps"] = value.ProtocolStart,
            ["pf"] = value.ProtocolFinish,
            ["ss"] = value.SourcePortStart,
            ["sf"] = value.SourcePortFinish,
            ["ds"] = value.DestinationPortStart,
            ["df"] = value.DestinationPortFinish,
            ["k"] = value.Kind
        };

        return JsonSerializer.Serialize(payload, JsonOptions);
    }

    /// <summary>
    /// JSON 文字列からサービス値を復元します。
    /// </summary>
    /// <param name="value">復元元の JSON 文字列。</param>
    /// <returns>復元したサービス値。</returns>
    public static ServiceValue DeserializeServiceValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException("service_json must not be empty.");
        }

        using var document = JsonDocument.Parse(value);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("service_json must be a JSON object.");
        }

        return new ServiceValue
        {
            ProtocolStart = ReadRequiredUInt32Value(root, "ps"),
            ProtocolFinish = ReadRequiredUInt32Value(root, "pf"),
            SourcePortStart = ReadRequiredUInt32Value(root, "ss"),
            SourcePortFinish = ReadRequiredUInt32Value(root, "sf"),
            DestinationPortStart = ReadRequiredUInt32Value(root, "ds"),
            DestinationPortFinish = ReadRequiredUInt32Value(root, "df"),
            Kind = ReadOptionalStringValue(root, "k")
        };
    }

    /// <summary>
    /// アドレス値一覧を JSON 文字列へ変換します。
    /// </summary>
    /// <param name="values">変換するアドレス値一覧。</param>
    /// <returns>JSON 文字列。</returns>
    public static string SerializeAddressValues(IEnumerable<AddressValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        var payload = values
            .Select(static value => new Dictionary<string, uint>
            {
                ["s"] = value.Start,
                ["f"] = value.Finish
            })
            .ToArray();

        return JsonSerializer.Serialize(payload, JsonOptions);
    }

    /// <summary>
    /// JSON 文字列からアドレス値一覧を復元します。
    /// </summary>
    /// <param name="value">復元元の JSON 文字列。</param>
    /// <returns>復元したアドレス値一覧。</returns>
    public static IReadOnlyList<AddressValue> DeserializeAddressValues(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        using var document = JsonDocument.Parse(value);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new FormatException("address_values_json must be a JSON array.");
        }

        var items = new List<AddressValue>();
        foreach (var element in document.RootElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                throw new FormatException("address_values_json contains an unsupported element.");
            }

            items.Add(new AddressValue
            {
                Start = ReadRequiredUInt32Value(element, "s"),
                Finish = ReadRequiredUInt32Value(element, "f")
            });
        }

        return items;
    }

    /// <summary>
    /// サービス値一覧を JSON 文字列へ変換します。
    /// </summary>
    /// <param name="values">変換するサービス値一覧。</param>
    /// <returns>JSON 文字列。</returns>
    public static string SerializeServiceValues(IEnumerable<ServiceValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        var payload = values
            .Select(static value => new Dictionary<string, object?>
            {
                ["ps"] = value.ProtocolStart,
                ["pf"] = value.ProtocolFinish,
                ["ss"] = value.SourcePortStart,
                ["sf"] = value.SourcePortFinish,
                ["ds"] = value.DestinationPortStart,
                ["df"] = value.DestinationPortFinish,
                ["k"] = value.Kind
            })
            .ToArray();

        return JsonSerializer.Serialize(payload, JsonOptions);
    }

    /// <summary>
    /// JSON 文字列からサービス値一覧を復元します。
    /// </summary>
    /// <param name="value">復元元の JSON 文字列。</param>
    /// <returns>復元したサービス値一覧。</returns>
    public static IReadOnlyList<ServiceValue> DeserializeServiceValues(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        using var document = JsonDocument.Parse(value);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new FormatException("service_values_json must be a JSON array.");
        }

        var items = new List<ServiceValue>();
        foreach (var element in document.RootElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                throw new FormatException("service_values_json contains an unsupported element.");
            }

            items.Add(new ServiceValue
            {
                ProtocolStart = ReadRequiredUInt32Value(element, "ps"),
                ProtocolFinish = ReadRequiredUInt32Value(element, "pf"),
                SourcePortStart = ReadRequiredUInt32Value(element, "ss"),
                SourcePortFinish = ReadRequiredUInt32Value(element, "sf"),
                DestinationPortStart = ReadRequiredUInt32Value(element, "ds"),
                DestinationPortFinish = ReadRequiredUInt32Value(element, "df"),
                Kind = ReadOptionalStringValue(element, "k")
            });
        }

        return items;
    }

    private static string? ReadOptionalStringValue(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String => property.GetString(),
            JsonValueKind.Number => property.GetRawText(),
            _ => throw new FormatException($"services_json '{propertyName}' has unsupported type.")
        };
    }

    private static uint ReadRequiredUInt32Value(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property))
        {
            throw new FormatException($"json object must contain '{propertyName}'.");
        }

        return property.ValueKind switch
        {
            JsonValueKind.Number when property.TryGetUInt32(out var numericValue) => numericValue,
            JsonValueKind.String when uint.TryParse(property.GetString(), out var stringValue) => stringValue,
            _ => throw new FormatException($"json '{propertyName}' has unsupported type.")
        };
    }

}
