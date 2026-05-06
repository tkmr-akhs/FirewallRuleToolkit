namespace FirewallRuleToolkit.Infra.Csv;

/// <summary>
/// CSV 入出力で使用するヘッダー レイアウトを定義します。
/// </summary>
internal static class CsvDatabaseLayout
{
    public static class AtomicSecurityPolicies
    {
        public const string FromZoneHeader = "from_zone";
        public const string SourceAddressJsonHeader = "source_address_json";
        public const string ToZoneHeader = "to_zone";
        public const string DestinationAddressJsonHeader = "destination_address_json";
        public const string ApplicationHeader = "application";
        public const string ServiceJsonHeader = "service_json";
        public const string ActionHeader = "action";
        public const string GroupIdHeader = "group_id";
        public const string OriginalIndexHeader = "original_index";
        public const string OriginalPolicyNameHeader = "original_policy_name";

        public static readonly string[] Headers =
        [
            FromZoneHeader,
            SourceAddressJsonHeader,
            ToZoneHeader,
            DestinationAddressJsonHeader,
            ApplicationHeader,
            ServiceJsonHeader,
            ActionHeader,
            GroupIdHeader,
            OriginalIndexHeader,
            OriginalPolicyNameHeader
        ];
    }

    public static class MergedSecurityPolicies
    {
        public const string FromZonesHeader = "from_zones";
        public const string SourceAddressesHeader = "source_addresses";
        public const string ToZonesHeader = "to_zones";
        public const string DestinationAddressesHeader = "destination_addresses";
        public const string ApplicationsHeader = "applications";
        public const string ServicesHeader = "services";
        public const string ActionHeader = "action";
        public const string GroupIdHeader = "group_id";
        public const string MinimumIndexHeader = "minimum_index";
        public const string MaximumIndexHeader = "maximum_index";
        public const string OriginalPolicyNamesHeader = "original_policy_names";

        public static readonly string[] Headers =
        [
            FromZonesHeader,
            SourceAddressesHeader,
            ToZonesHeader,
            DestinationAddressesHeader,
            ApplicationsHeader,
            ServicesHeader,
            ActionHeader,
            GroupIdHeader,
            MinimumIndexHeader,
            MaximumIndexHeader,
            OriginalPolicyNamesHeader
        ];
    }

    public static class PaloAltoAddressDefinitions
    {
        public const string NameHeader = "名前";
        public const string AddressHeader = "アドレス";
    }

    public static class PaloAltoAddressGroups
    {
        public const string NameHeader = "名前";
        public const string AddressHeader = "アドレス";
    }

    public static class PaloAltoServiceDefinitions
    {
        public const string NameHeader = "名前";
        public const string ProtocolHeader = "プロトコル";
        public const string SourcePortHeader = "送信元ポート";
        public const string DestinationPortHeader = "宛先ポート";
    }

    public static class PaloAltoServiceGroups
    {
        public const string NameHeader = "名前";
        public const string ServiceHeader = "サービス";
    }

    public static class PaloAltoSecurityPolicies
    {
        public const string IndexHeader = "";
        public const string NameHeader = "名前";
        public const string FromZoneHeader = "送信元 ゾーン";
        public const string SourceAddressHeader = "送信元 アドレス";
        public const string ToZoneHeader = "宛先 ゾーン";
        public const string DestinationAddressHeader = "宛先 アドレス";
        public const string ApplicationHeader = "アプリケーション";
        public const string ServiceHeader = "サービス";
        public const string ActionHeader = "アクション";
        public const string RuleUsageContentHeader = "ルールの使用状況 内容";
    }
}
