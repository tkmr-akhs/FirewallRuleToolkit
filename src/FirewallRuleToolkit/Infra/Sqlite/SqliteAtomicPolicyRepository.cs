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
    private const string AddressStartJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.AddressStartJsonPath;
    private const string AddressFinishJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.AddressFinishJsonPath;
    private const string ServiceProtocolStartJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceProtocolStartJsonPath;
    private const string ServiceProtocolFinishJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceProtocolFinishJsonPath;
    private const string ServiceSourcePortStartJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceSourcePortStartJsonPath;
    private const string ServiceSourcePortFinishJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceSourcePortFinishJsonPath;
    private const string ServiceDestinationPortStartJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceDestinationPortStartJsonPath;
    private const string ServiceDestinationPortFinishJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceDestinationPortFinishJsonPath;
    private const string ServiceKindJsonPath = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceKindJsonPath;
    private const string SourceAddressStartExpression = "json_extract(" + SourceAddressJsonColumn + ", '" + AddressStartJsonPath + "')";
    private const string SourceAddressFinishExpression = "json_extract(" + SourceAddressJsonColumn + ", '" + AddressFinishJsonPath + "')";
    private const string DestinationAddressStartExpression = "json_extract(" + DestinationAddressJsonColumn + ", '" + AddressStartJsonPath + "')";
    private const string DestinationAddressFinishExpression = "json_extract(" + DestinationAddressJsonColumn + ", '" + AddressFinishJsonPath + "')";
    private const string ServiceProtocolStartExpression = "json_extract(" + ServiceJsonColumn + ", '" + ServiceProtocolStartJsonPath + "')";
    private const string ServiceProtocolFinishExpression = "json_extract(" + ServiceJsonColumn + ", '" + ServiceProtocolFinishJsonPath + "')";
    private const string ServiceSourcePortStartExpression = "json_extract(" + ServiceJsonColumn + ", '" + ServiceSourcePortStartJsonPath + "')";
    private const string ServiceSourcePortFinishExpression = "json_extract(" + ServiceJsonColumn + ", '" + ServiceSourcePortFinishJsonPath + "')";
    private const string ServiceDestinationPortStartExpression = "json_extract(" + ServiceJsonColumn + ", '" + ServiceDestinationPortStartJsonPath + "')";
    private const string ServiceDestinationPortFinishExpression = "json_extract(" + ServiceJsonColumn + ", '" + ServiceDestinationPortFinishJsonPath + "')";
    private const string ServiceKindExpression = "json_extract(" + ServiceJsonColumn + ", '" + ServiceKindJsonPath + "')";
    private const string ServiceCategoryOrderExpression =
        "CASE " +
        "WHEN " + ServiceKindExpression + " IS NULL " +
        "AND " + ServiceProtocolStartExpression + " = 0 " +
        "AND " + ServiceProtocolFinishExpression + " = 255 " +
        "AND " + ServiceSourcePortStartExpression + " = 0 " +
        "AND " + ServiceSourcePortFinishExpression + " = 65535 " +
        "AND " + ServiceDestinationPortStartExpression + " = 0 " +
        "AND " + ServiceDestinationPortFinishExpression + " = 65535 THEN 0 " +
        "WHEN " + ServiceKindExpression + " IS NOT NULL AND trim(" + ServiceKindExpression + ") <> '' THEN 1 " +
        "ELSE 2 END";
    private const string DestinationAddressOrderColumns =
        DestinationAddressStartExpression + ", " +
        DestinationAddressFinishExpression;
    private const string SourceAddressOrderColumns =
        SourceAddressStartExpression + ", " +
        SourceAddressFinishExpression;
    private const string ServiceOrderColumns =
        ServiceCategoryOrderExpression + ", " +
        ServiceKindExpression + ", " +
        ServiceProtocolStartExpression + ", " +
        ServiceProtocolFinishExpression + ", " +
        ServiceDestinationPortStartExpression + ", " +
        ServiceDestinationPortFinishExpression + ", " +
        ServiceSourcePortStartExpression + ", " +
        ServiceSourcePortFinishExpression;
    private const string CanonicalConditionOrderColumns =
        DestinationAddressOrderColumns + ", " +
        ServiceOrderColumns + ", " +
        ApplicationColumn + ", " +
        SourceAddressOrderColumns;

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
        " ORDER BY " +
        OriginalIndexColumn + ", " +
        FromZoneColumn + ", " +
        ToZoneColumn + ", " +
        ActionColumn + ", " +
        CanonicalConditionOrderColumns + ", " +
        "rowid;";

    private const string SelectAllOrderedForMergeCommandText =
        "SELECT " + SelectColumns +
        " FROM " + TableName +
        " ORDER BY " +
        FromZoneColumn + ", " +
        ToZoneColumn + ", " +
        ServiceKindExpression + ", " +
        OriginalIndexColumn + ", " +
        CanonicalConditionOrderColumns + ", " +
        ActionColumn + ", " +
        "rowid;";

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
    /// <returns>`FromZone`、`ToZone`、`Service.Kind`、`OriginalIndex`、標準条件順、保存順の順に整列された原子的なセキュリティ ポリシー列。</returns>
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
