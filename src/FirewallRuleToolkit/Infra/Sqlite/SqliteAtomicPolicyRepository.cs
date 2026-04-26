using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// 原子的なセキュリティ ポリシーを SQLite で読み書きします。
/// </summary>
public sealed class SqliteAtomicPolicyRepository : SqliteReadWriteRepositoryBase<AtomicSecurityPolicy>, IAtomicPolicyMergeSource
{
    private const string TableName = SqliteDatabaseLayout.AtomicSecurityPolicies.TableName;
    private const string FromZoneColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.FromZoneColumn;
    private const string SourceAddressJsonColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.SourceAddressJsonColumn;
    private const string ToZoneColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ToZoneColumn;
    private const string DestinationAddressJsonColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.DestinationAddressJsonColumn;
    private const string ApplicationColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ApplicationColumn;
    private const string ServiceJsonColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceJsonColumn;
    private const string ActionColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ActionColumn;
    private const string GroupIdColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.GroupIdColumn;
    private const string OriginalIndexColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.OriginalIndexColumn;
    private const string OriginalPolicyNameColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.OriginalPolicyNameColumn;
    private const string ServiceKindJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceKindJsonPath;

    private const string InitializeCommandText =
        "DROP TABLE IF EXISTS " + TableName + ";" +
        "CREATE TABLE " + TableName + " (" +
        FromZoneColumn + " TEXT NOT NULL, " +
        SourceAddressJsonColumn + " TEXT NOT NULL, " +
        ToZoneColumn + " TEXT NOT NULL, " +
        DestinationAddressJsonColumn + " TEXT NOT NULL, " +
        ApplicationColumn + " TEXT NOT NULL, " +
        ServiceJsonColumn + " TEXT NOT NULL, " +
        ActionColumn + " TEXT NOT NULL, " +
        GroupIdColumn + " TEXT NOT NULL, " +
        OriginalIndexColumn + " INTEGER NOT NULL CHECK (" + OriginalIndexColumn + " >= 0 AND " + OriginalIndexColumn + " <= 4294967295), " +
        OriginalPolicyNameColumn + " TEXT NOT NULL" +
        ");";

    private const string SelectColumns =
        FromZoneColumn + ", " +
        SourceAddressJsonColumn + ", " +
        ToZoneColumn + ", " +
        DestinationAddressJsonColumn + ", " +
        ApplicationColumn + ", " +
        ServiceJsonColumn + ", " +
        ActionColumn + ", " +
        GroupIdColumn + ", " +
        OriginalIndexColumn + ", " +
        OriginalPolicyNameColumn;

    private const string SelectAllCommandText =
        "SELECT " + SelectColumns +
        " FROM " + TableName +
        " ORDER BY " + OriginalIndexColumn + ", rowid;";

    private const string SelectAllOrderedForMergeCommandText =
        "SELECT " + SelectColumns +
        " FROM " + TableName +
        " ORDER BY " +
        FromZoneColumn + ", " +
        ToZoneColumn + ", " +
        "json_extract(" + ServiceJsonColumn + ", '" + ServiceKindJsonPath + "'), " +
        OriginalIndexColumn + ", rowid;";

    private const string InsertCommandText =
        "INSERT INTO " + TableName + "(" + SelectColumns + ") " +
        "VALUES ($fromZone, $sourceAddressJson, $toZone, $destinationAddressJson, $application, $serviceJson, $action, $groupId, $originalIndex, $originalPolicyName);";

    /// <summary>
    /// 原子的なセキュリティ ポリシーを SQLite で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    public SqliteAtomicPolicyRepository(string databaseDirectory)
        : base(
            databaseDirectory,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            ReadRecord,
            static (command, atomicPolicy) =>
            {
                command.Parameters.AddWithValue("$fromZone", atomicPolicy.FromZone);
                command.Parameters.AddWithValue("$sourceAddressJson", EntityValueCodec.SerializeAddressValue(atomicPolicy.SourceAddress));
                command.Parameters.AddWithValue("$toZone", atomicPolicy.ToZone);
                command.Parameters.AddWithValue("$destinationAddressJson", EntityValueCodec.SerializeAddressValue(atomicPolicy.DestinationAddress));
                command.Parameters.AddWithValue("$application", atomicPolicy.Application);
                command.Parameters.AddWithValue("$serviceJson", EntityValueCodec.SerializeServiceValue(atomicPolicy.Service));
                command.Parameters.AddWithValue("$action", EntityValueCodec.FormatAction(atomicPolicy.Action));
                command.Parameters.AddWithValue("$groupId", atomicPolicy.GroupId);
                command.Parameters.AddWithValue("$originalIndex", EntityValueCodec.FormatPolicyIndex(atomicPolicy.OriginalIndex));
                command.Parameters.AddWithValue("$originalPolicyName", atomicPolicy.OriginalPolicyName);
            })
    {
    }

    internal SqliteAtomicPolicyRepository(SqliteWriteTransaction writeTransaction)
        : base(
            writeTransaction,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            ReadRecord,
            static (command, atomicPolicy) =>
            {
                command.Parameters.AddWithValue("$fromZone", atomicPolicy.FromZone);
                command.Parameters.AddWithValue("$sourceAddressJson", EntityValueCodec.SerializeAddressValue(atomicPolicy.SourceAddress));
                command.Parameters.AddWithValue("$toZone", atomicPolicy.ToZone);
                command.Parameters.AddWithValue("$destinationAddressJson", EntityValueCodec.SerializeAddressValue(atomicPolicy.DestinationAddress));
                command.Parameters.AddWithValue("$application", atomicPolicy.Application);
                command.Parameters.AddWithValue("$serviceJson", EntityValueCodec.SerializeServiceValue(atomicPolicy.Service));
                command.Parameters.AddWithValue("$action", EntityValueCodec.FormatAction(atomicPolicy.Action));
                command.Parameters.AddWithValue("$groupId", atomicPolicy.GroupId);
                command.Parameters.AddWithValue("$originalIndex", EntityValueCodec.FormatPolicyIndex(atomicPolicy.OriginalIndex));
                command.Parameters.AddWithValue("$originalPolicyName", atomicPolicy.OriginalPolicyName);
            })
    {
    }

    /// <summary>
    /// merge 処理に適した順序で原子的なセキュリティ ポリシーを取得します。
    /// </summary>
    /// <returns>`FromZone`、`ToZone`、`Service.Kind`、`OriginalIndex`、保存順の順に整列された原子的なセキュリティ ポリシー列。</returns>
    public IEnumerable<AtomicSecurityPolicy> GetAllOrderedForMerge()
    {
        using var connection = SqliteRepositoryHelper.OpenConnection(DatabasePath);
        using var command = connection.CreateCommand();
        command.CommandText = SelectAllOrderedForMergeCommandText;

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            yield return ReadRecord(reader);
        }
    }

    /// <inheritdoc />
    public override void EnsureAvailable()
    {
        SqliteRepositoryHelper.EnsureTableAvailable(
            DatabasePath,
            TableName,
            "Atomic policies are unavailable. Run atomize before export/stat.");
    }

    private static AtomicSecurityPolicy ReadRecord(SqliteDataReader reader)
    {
        return new AtomicSecurityPolicy
        {
            FromZone = reader.GetString(0),
            SourceAddress = EntityValueCodec.DeserializeAddressValue(reader.GetString(1)),
            ToZone = reader.GetString(2),
            DestinationAddress = EntityValueCodec.DeserializeAddressValue(reader.GetString(3)),
            Application = reader.GetString(4),
            Service = EntityValueCodec.DeserializeServiceValue(reader.GetString(5)),
            Action = EntityValueCodec.ParseAction(reader.GetString(6)),
            GroupId = reader.GetString(7),
            OriginalIndex = EntityValueCodec.ReadPolicyIndex(reader.GetInt64(8)),
            OriginalPolicyName = reader.GetString(9)
        };
    }
}
