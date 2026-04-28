namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// 統合済みセキュリティ ポリシーを SQLite で読み書きします。
/// </summary>
public sealed class SqliteMergedSecurityPolicyRepository : SqliteReadWriteRepositoryBase<MergedSecurityPolicy>
{
    private const string TableName = SqliteDatabaseLayout.MergedSecurityPolicies.TableName;
    private const string FromZoneJsonColumn = SqliteDatabaseLayout.MergedSecurityPolicies.FromZoneJsonColumn;
    private const string SourceAddressesJsonColumn = SqliteDatabaseLayout.MergedSecurityPolicies.SourceAddressesJsonColumn;
    private const string ToZoneJsonColumn = SqliteDatabaseLayout.MergedSecurityPolicies.ToZoneJsonColumn;
    private const string DestinationAddressesJsonColumn = SqliteDatabaseLayout.MergedSecurityPolicies.DestinationAddressesJsonColumn;
    private const string ApplicationJsonColumn = SqliteDatabaseLayout.MergedSecurityPolicies.ApplicationJsonColumn;
    private const string ServicesJsonColumn = SqliteDatabaseLayout.MergedSecurityPolicies.ServicesJsonColumn;
    private const string ActionColumn = SqliteDatabaseLayout.MergedSecurityPolicies.ActionColumn;
    private const string GroupIdColumn = SqliteDatabaseLayout.MergedSecurityPolicies.GroupIdColumn;
    private const string MinimumIndexColumn = SqliteDatabaseLayout.MergedSecurityPolicies.MinimumIndexColumn;
    private const string MaximumIndexColumn = SqliteDatabaseLayout.MergedSecurityPolicies.MaximumIndexColumn;
    private const string OriginalPolicyNamesJsonColumn = SqliteDatabaseLayout.MergedSecurityPolicies.OriginalPolicyNamesJsonColumn;

    private const string InitializeCommandText =
        "DROP TABLE IF EXISTS " + TableName + ";" +
        "CREATE TABLE " + TableName + " (" +
        FromZoneJsonColumn + " TEXT NOT NULL, " +
        SourceAddressesJsonColumn + " TEXT NOT NULL, " +
        ToZoneJsonColumn + " TEXT NOT NULL, " +
        DestinationAddressesJsonColumn + " TEXT NOT NULL, " +
        ApplicationJsonColumn + " TEXT NOT NULL, " +
        ServicesJsonColumn + " TEXT NOT NULL, " +
        ActionColumn + " TEXT NOT NULL, " +
        GroupIdColumn + " TEXT NOT NULL, " +
        MinimumIndexColumn + " INTEGER NOT NULL CHECK (" + MinimumIndexColumn + " >= 0 AND " + MinimumIndexColumn + " <= 4294967295), " +
        MaximumIndexColumn + " INTEGER NOT NULL CHECK (" + MaximumIndexColumn + " >= 0 AND " + MaximumIndexColumn + " <= 4294967295), " +
        OriginalPolicyNamesJsonColumn + " TEXT NOT NULL" +
        ");";

    private const string SelectColumns =
        FromZoneJsonColumn + ", " +
        SourceAddressesJsonColumn + ", " +
        ToZoneJsonColumn + ", " +
        DestinationAddressesJsonColumn + ", " +
        ApplicationJsonColumn + ", " +
        ServicesJsonColumn + ", " +
        ActionColumn + ", " +
        GroupIdColumn + ", " +
        MinimumIndexColumn + ", " +
        MaximumIndexColumn + ", " +
        OriginalPolicyNamesJsonColumn;

    private const string SelectAllCommandText =
        "SELECT " + SelectColumns +
        " FROM " + TableName +
        " ORDER BY " + MinimumIndexColumn + ", " + MaximumIndexColumn + ", rowid;";

    private const string InsertCommandText =
        "INSERT INTO " + TableName + "(" + SelectColumns + ") " +
        "VALUES ($fromZoneJson, $sourceAddressesJson, $toZoneJson, $destinationAddressesJson, $applicationJson, $servicesJson, $action, $groupId, $minimumIndex, $maximumIndex, $originalPolicyNamesJson);";

    /// <summary>
    /// 統合済みセキュリティ ポリシーを SQLite で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    public SqliteMergedSecurityPolicyRepository(string databaseDirectory)
        : base(
            databaseDirectory,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new MergedSecurityPolicy
            {
                FromZones = EntityValueCodec.DeserializeStringList(reader.GetString(0)).ToHashSet(StringComparer.Ordinal),
                SourceAddresses = EntityValueCodec.DeserializeAddressValues(reader.GetString(1)).ToHashSet(),
                ToZones = EntityValueCodec.DeserializeStringList(reader.GetString(2)).ToHashSet(StringComparer.Ordinal),
                DestinationAddresses = EntityValueCodec.DeserializeAddressValues(reader.GetString(3)).ToHashSet(),
                Applications = EntityValueCodec.DeserializeStringList(reader.GetString(4)).ToHashSet(StringComparer.Ordinal),
                Services = EntityValueCodec.DeserializeServiceValues(reader.GetString(5)).ToHashSet(),
                Action = EntityValueCodec.ParseAction(reader.GetString(6)),
                GroupId = reader.GetString(7),
                MinimumIndex = EntityValueCodec.ReadPolicyIndex(reader.GetInt64(8)),
                MaximumIndex = EntityValueCodec.ReadPolicyIndex(reader.GetInt64(9)),
                OriginalPolicyNames = EntityValueCodec.DeserializeOriginalPolicyNames(reader.GetString(10))
            },
            static (command, policy) =>
            {
                command.Parameters.AddWithValue("$fromZoneJson", EntityValueCodec.SerializeStringList(policy.FromZones));
                command.Parameters.AddWithValue("$sourceAddressesJson", EntityValueCodec.SerializeAddressValues(policy.SourceAddresses));
                command.Parameters.AddWithValue("$toZoneJson", EntityValueCodec.SerializeStringList(policy.ToZones));
                command.Parameters.AddWithValue("$destinationAddressesJson", EntityValueCodec.SerializeAddressValues(policy.DestinationAddresses));
                command.Parameters.AddWithValue("$applicationJson", EntityValueCodec.SerializeStringList(policy.Applications));
                command.Parameters.AddWithValue("$servicesJson", EntityValueCodec.SerializeServiceValues(policy.Services));
                command.Parameters.AddWithValue("$action", EntityValueCodec.FormatAction(policy.Action));
                command.Parameters.AddWithValue("$groupId", policy.GroupId);
                command.Parameters.AddWithValue("$minimumIndex", EntityValueCodec.FormatPolicyIndex(policy.MinimumIndex));
                command.Parameters.AddWithValue("$maximumIndex", EntityValueCodec.FormatPolicyIndex(policy.MaximumIndex));
                command.Parameters.AddWithValue("$originalPolicyNamesJson", EntityValueCodec.SerializeOriginalPolicyNames(policy.OriginalPolicyNames));
            })
    {
    }

    internal SqliteMergedSecurityPolicyRepository(SqliteWriteTransaction writeTransaction)
        : base(
            writeTransaction,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new MergedSecurityPolicy
            {
                FromZones = EntityValueCodec.DeserializeStringList(reader.GetString(0)).ToHashSet(StringComparer.Ordinal),
                SourceAddresses = EntityValueCodec.DeserializeAddressValues(reader.GetString(1)).ToHashSet(),
                ToZones = EntityValueCodec.DeserializeStringList(reader.GetString(2)).ToHashSet(StringComparer.Ordinal),
                DestinationAddresses = EntityValueCodec.DeserializeAddressValues(reader.GetString(3)).ToHashSet(),
                Applications = EntityValueCodec.DeserializeStringList(reader.GetString(4)).ToHashSet(StringComparer.Ordinal),
                Services = EntityValueCodec.DeserializeServiceValues(reader.GetString(5)).ToHashSet(),
                Action = EntityValueCodec.ParseAction(reader.GetString(6)),
                GroupId = reader.GetString(7),
                MinimumIndex = EntityValueCodec.ReadPolicyIndex(reader.GetInt64(8)),
                MaximumIndex = EntityValueCodec.ReadPolicyIndex(reader.GetInt64(9)),
                OriginalPolicyNames = EntityValueCodec.DeserializeOriginalPolicyNames(reader.GetString(10))
            },
            static (command, policy) =>
            {
                command.Parameters.AddWithValue("$fromZoneJson", EntityValueCodec.SerializeStringList(policy.FromZones));
                command.Parameters.AddWithValue("$sourceAddressesJson", EntityValueCodec.SerializeAddressValues(policy.SourceAddresses));
                command.Parameters.AddWithValue("$toZoneJson", EntityValueCodec.SerializeStringList(policy.ToZones));
                command.Parameters.AddWithValue("$destinationAddressesJson", EntityValueCodec.SerializeAddressValues(policy.DestinationAddresses));
                command.Parameters.AddWithValue("$applicationJson", EntityValueCodec.SerializeStringList(policy.Applications));
                command.Parameters.AddWithValue("$servicesJson", EntityValueCodec.SerializeServiceValues(policy.Services));
                command.Parameters.AddWithValue("$action", EntityValueCodec.FormatAction(policy.Action));
                command.Parameters.AddWithValue("$groupId", policy.GroupId);
                command.Parameters.AddWithValue("$minimumIndex", EntityValueCodec.FormatPolicyIndex(policy.MinimumIndex));
                command.Parameters.AddWithValue("$maximumIndex", EntityValueCodec.FormatPolicyIndex(policy.MaximumIndex));
                command.Parameters.AddWithValue("$originalPolicyNamesJson", EntityValueCodec.SerializeOriginalPolicyNames(policy.OriginalPolicyNames));
            })
    {
    }

    /// <inheritdoc />
    public override void EnsureAvailable()
    {
        SqliteRepositoryHelper.EnsureTableAvailable(
            DatabasePath,
            TableName,
            "Merged security policies are unavailable. Run merge before export/stat.");
    }
}
