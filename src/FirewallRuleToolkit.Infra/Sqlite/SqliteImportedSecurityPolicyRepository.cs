namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// import 直後の未解決セキュリティ ポリシーを SQLite で読み書きします。
/// </summary>
public sealed class SqliteImportedSecurityPolicyRepository : SqliteReadWriteRepositoryBase<ImportedSecurityPolicy>
{
    private const string TableName = SqliteDatabaseLayout.SecurityPolicies.TableName;
    private const string PolicyIndexColumn = SqliteDatabaseLayout.SecurityPolicies.PolicyIndexColumn;
    private const string NameColumn = SqliteDatabaseLayout.SecurityPolicies.NameColumn;
    private const string FromZoneJsonColumn = SqliteDatabaseLayout.SecurityPolicies.FromZoneJsonColumn;
    private const string SourceAddressesJsonColumn = SqliteDatabaseLayout.SecurityPolicies.SourceAddressesJsonColumn;
    private const string ToZoneJsonColumn = SqliteDatabaseLayout.SecurityPolicies.ToZoneJsonColumn;
    private const string DestinationAddressesJsonColumn = SqliteDatabaseLayout.SecurityPolicies.DestinationAddressesJsonColumn;
    private const string ApplicationJsonColumn = SqliteDatabaseLayout.SecurityPolicies.ApplicationJsonColumn;
    private const string ServicesJsonColumn = SqliteDatabaseLayout.SecurityPolicies.ServicesJsonColumn;
    private const string ActionColumn = SqliteDatabaseLayout.SecurityPolicies.ActionColumn;
    private const string GroupIdColumn = SqliteDatabaseLayout.SecurityPolicies.GroupIdColumn;

    private const string InitializeCommandText =
        "DROP TABLE IF EXISTS " + TableName + ";" +
        "CREATE TABLE " + TableName + " (" +
        NameColumn + " TEXT NOT NULL PRIMARY KEY, " +
        PolicyIndexColumn + " INTEGER NOT NULL UNIQUE CHECK (" + PolicyIndexColumn + " >= 0 AND " + PolicyIndexColumn + " <= 4294967295), " +
        FromZoneJsonColumn + " TEXT NOT NULL, " +
        SourceAddressesJsonColumn + " TEXT NOT NULL, " +
        ToZoneJsonColumn + " TEXT NOT NULL, " +
        DestinationAddressesJsonColumn + " TEXT NOT NULL, " +
        ApplicationJsonColumn + " TEXT NOT NULL, " +
        ServicesJsonColumn + " TEXT NOT NULL, " +
        ActionColumn + " TEXT NOT NULL, " +
        GroupIdColumn + " TEXT NOT NULL" +
        ");";

    private const string SelectAllCommandText =
        "SELECT " +
        PolicyIndexColumn + ", " +
        NameColumn + ", " +
        FromZoneJsonColumn + ", " +
        SourceAddressesJsonColumn + ", " +
        ToZoneJsonColumn + ", " +
        DestinationAddressesJsonColumn + ", " +
        ApplicationJsonColumn + ", " +
        ServicesJsonColumn + ", " +
        ActionColumn + ", " +
        GroupIdColumn +
        " FROM " + TableName +
        " ORDER BY " + PolicyIndexColumn + ";";

    private const string InsertCommandText =
        "INSERT INTO " + TableName + "(" +
        PolicyIndexColumn + ", " +
        NameColumn + ", " +
        FromZoneJsonColumn + ", " +
        SourceAddressesJsonColumn + ", " +
        ToZoneJsonColumn + ", " +
        DestinationAddressesJsonColumn + ", " +
        ApplicationJsonColumn + ", " +
        ServicesJsonColumn + ", " +
        ActionColumn + ", " +
        GroupIdColumn + ") " +
        "VALUES ($index, $name, $fromZoneJson, $sourceAddressesJson, $toZoneJson, $destinationAddressesJson, $applicationJson, $servicesJson, $action, $groupId);";

    /// <summary>
    /// import 直後の未解決セキュリティ ポリシーを SQLite で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    public SqliteImportedSecurityPolicyRepository(string databaseDirectory)
        : base(
            databaseDirectory,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new ImportedSecurityPolicy
            {
                Index = EntityValueCodec.ReadPolicyIndex(reader.GetInt64(0)),
                Name = reader.GetString(1),
                FromZones = EntityValueCodec.DeserializeStringList(reader.GetString(2)),
                SourceAddressReferences = EntityValueCodec.DeserializeStringList(reader.GetString(3)),
                ToZones = EntityValueCodec.DeserializeStringList(reader.GetString(4)),
                DestinationAddressReferences = EntityValueCodec.DeserializeStringList(reader.GetString(5)),
                Applications = EntityValueCodec.DeserializeStringList(reader.GetString(6)),
                ServiceReferences = EntityValueCodec.DeserializeStringList(reader.GetString(7)),
                Action = EntityValueCodec.ParseAction(reader.GetString(8)),
                GroupId = reader.GetString(9)
            },
            static (command, securityPolicy) =>
            {
                command.Parameters.AddWithValue("$index", EntityValueCodec.FormatPolicyIndex(securityPolicy.Index));
                command.Parameters.AddWithValue("$name", securityPolicy.Name);
                command.Parameters.AddWithValue("$fromZoneJson", EntityValueCodec.SerializeStringList(securityPolicy.FromZones));
                command.Parameters.AddWithValue("$sourceAddressesJson", EntityValueCodec.SerializeStringList(securityPolicy.SourceAddressReferences));
                command.Parameters.AddWithValue("$toZoneJson", EntityValueCodec.SerializeStringList(securityPolicy.ToZones));
                command.Parameters.AddWithValue("$destinationAddressesJson", EntityValueCodec.SerializeStringList(securityPolicy.DestinationAddressReferences));
                command.Parameters.AddWithValue("$applicationJson", EntityValueCodec.SerializeStringList(securityPolicy.Applications));
                command.Parameters.AddWithValue("$servicesJson", EntityValueCodec.SerializeStringList(securityPolicy.ServiceReferences));
                command.Parameters.AddWithValue("$action", EntityValueCodec.FormatAction(securityPolicy.Action));
                command.Parameters.AddWithValue("$groupId", securityPolicy.GroupId);
            })
    {
    }

    internal SqliteImportedSecurityPolicyRepository(SqliteWriteTransaction writeTransaction)
        : base(
            writeTransaction,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new ImportedSecurityPolicy
            {
                Index = EntityValueCodec.ReadPolicyIndex(reader.GetInt64(0)),
                Name = reader.GetString(1),
                FromZones = EntityValueCodec.DeserializeStringList(reader.GetString(2)),
                SourceAddressReferences = EntityValueCodec.DeserializeStringList(reader.GetString(3)),
                ToZones = EntityValueCodec.DeserializeStringList(reader.GetString(4)),
                DestinationAddressReferences = EntityValueCodec.DeserializeStringList(reader.GetString(5)),
                Applications = EntityValueCodec.DeserializeStringList(reader.GetString(6)),
                ServiceReferences = EntityValueCodec.DeserializeStringList(reader.GetString(7)),
                Action = EntityValueCodec.ParseAction(reader.GetString(8)),
                GroupId = reader.GetString(9)
            },
            static (command, securityPolicy) =>
            {
                command.Parameters.AddWithValue("$index", EntityValueCodec.FormatPolicyIndex(securityPolicy.Index));
                command.Parameters.AddWithValue("$name", securityPolicy.Name);
                command.Parameters.AddWithValue("$fromZoneJson", EntityValueCodec.SerializeStringList(securityPolicy.FromZones));
                command.Parameters.AddWithValue("$sourceAddressesJson", EntityValueCodec.SerializeStringList(securityPolicy.SourceAddressReferences));
                command.Parameters.AddWithValue("$toZoneJson", EntityValueCodec.SerializeStringList(securityPolicy.ToZones));
                command.Parameters.AddWithValue("$destinationAddressesJson", EntityValueCodec.SerializeStringList(securityPolicy.DestinationAddressReferences));
                command.Parameters.AddWithValue("$applicationJson", EntityValueCodec.SerializeStringList(securityPolicy.Applications));
                command.Parameters.AddWithValue("$servicesJson", EntityValueCodec.SerializeStringList(securityPolicy.ServiceReferences));
                command.Parameters.AddWithValue("$action", EntityValueCodec.FormatAction(securityPolicy.Action));
                command.Parameters.AddWithValue("$groupId", securityPolicy.GroupId);
            })
    {
    }

    /// <inheritdoc />
    public override void EnsureAvailable()
    {
        SqliteRepositoryHelper.EnsureTableAvailable(
            DatabasePath,
            TableName,
            "Security policies are unavailable. Run import before atomize.",
            requireExistingFile: false);
    }
}
