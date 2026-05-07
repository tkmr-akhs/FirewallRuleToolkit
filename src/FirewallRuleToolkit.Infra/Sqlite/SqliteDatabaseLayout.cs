namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// データベース ディレクトリ配下の SQLite ファイル/テーブル/列レイアウトを定義します。
/// </summary>
internal static class SqliteDatabaseLayout
{
    public const string DatabaseFileName = "database.sqlite";

    public static class AddressDefinitions
    {
        public const string TableName = "address_objects";
        public const string NameColumn = "name";
        public const string ValueColumn = "value";
    }

    public static class AddressGroupMembers
    {
        public const string TableName = "address_group_members";
        public const string GroupNameColumn = "group_name";
        public const string MemberNameColumn = "member_name";
        public const string GroupNameIndexName = "ix_address_group_members_group_name";
    }

    public static class ServiceDefinitions
    {
        public const string TableName = "service_objects";
        public const string NameColumn = "name";
        public const string ProtocolColumn = "protocol";
        public const string SourcePortColumn = "source_port";
        public const string DestinationPortColumn = "destination_port";
        public const string KindColumn = "kind";
    }

    public static class ServiceGroupMembers
    {
        public const string TableName = "service_group_members";
        public const string GroupNameColumn = "group_name";
        public const string MemberNameColumn = "member_name";
        public const string GroupNameIndexName = "ix_service_group_members_group_name";
    }

    public static class SecurityPolicies
    {
        public const string TableName = "security_policies";
        public const string PolicyIndexColumn = "policy_index";
        public const string NameColumn = "name";
        public const string FromZoneJsonColumn = "from_zone_json";
        public const string SourceAddressesJsonColumn = "source_addresses_json";
        public const string ToZoneJsonColumn = "to_zone_json";
        public const string DestinationAddressesJsonColumn = "destination_addresses_json";
        public const string ApplicationJsonColumn = "application_json";
        public const string ServicesJsonColumn = "services_json";
        public const string ActionColumn = "action";
        public const string GroupIdColumn = "group_id";
    }

    public static class AtomicSecurityPolicies
    {
        public const string TableName = "atomic_security_policies";
        public const string FromZoneColumn = "from_zone";
        public const string SourceAddressStartColumn = "source_address_start";
        public const string SourceAddressFinishColumn = "source_address_finish";
        public const string ToZoneColumn = "to_zone";
        public const string DestinationAddressStartColumn = "destination_address_start";
        public const string DestinationAddressFinishColumn = "destination_address_finish";
        public const string ApplicationColumn = "application";
        public const string ServiceCategoryOrderColumn = "service_category_order";
        public const string ServiceKindColumn = "service_kind";
        public const string ServiceProtocolStartColumn = "service_protocol_start";
        public const string ServiceProtocolFinishColumn = "service_protocol_finish";
        public const string ServiceSourcePortStartColumn = "service_source_port_start";
        public const string ServiceSourcePortFinishColumn = "service_source_port_finish";
        public const string ServiceDestinationPortStartColumn = "service_destination_port_start";
        public const string ServiceDestinationPortFinishColumn = "service_destination_port_finish";
        public const string ActionColumn = "action";
        public const string GroupIdColumn = "group_id";
        public const string OriginalIndexColumn = "original_index";
        public const string OriginalPolicyNameColumn = "original_policy_name";
        public const string MergeOrderIndexName = "ix_atomic_security_policies_merge_order";
        public const string DefaultOrderIndexName = "ix_atomic_security_policies_default_order";
    }

    public static class MergedSecurityPolicies
    {
        public const string TableName = "merged_security_policies";
        public const string FromZoneJsonColumn = "from_zone_json";
        public const string SourceAddressesJsonColumn = "source_addresses_json";
        public const string ToZoneJsonColumn = "to_zone_json";
        public const string DestinationAddressesJsonColumn = "destination_addresses_json";
        public const string ApplicationJsonColumn = "application_json";
        public const string ServicesJsonColumn = "services_json";
        public const string ActionColumn = "action";
        public const string GroupIdColumn = "group_id";
        public const string MinimumIndexColumn = "minimum_index";
        public const string MaximumIndexColumn = "maximum_index";
        public const string OriginalPolicyNamesJsonColumn = "original_policy_names_json";
    }

    public static class ToolMetadata
    {
        public const string TableName = "tool_metadata";
        public const string KeyColumn = "metadata_key";
        public const string ValueColumn = "metadata_value";
    }
}
