using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// 原子的なセキュリティ ポリシーを SQLite で読み書きします。
/// </summary>
public sealed class SqliteAtomicPolicyRepository : SqliteReadWriteRepositoryBase<AtomicSecurityPolicy>, IAtomicPolicyMergeSource
{
    private const string TableName = SqliteDatabaseLayout.AtomicSecurityPolicies.TableName;
    private const string FromZoneColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.FromZoneColumn;
    private const string SourceAddressStartColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.SourceAddressStartColumn;
    private const string SourceAddressFinishColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.SourceAddressFinishColumn;
    private const string ToZoneColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ToZoneColumn;
    private const string DestinationAddressStartColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.DestinationAddressStartColumn;
    private const string DestinationAddressFinishColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.DestinationAddressFinishColumn;
    private const string ApplicationColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ApplicationColumn;
    private const string ServiceCategoryOrderColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceCategoryOrderColumn;
    private const string ServiceKindColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceKindColumn;
    private const string ServiceProtocolStartColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceProtocolStartColumn;
    private const string ServiceProtocolFinishColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceProtocolFinishColumn;
    private const string ServiceSourcePortStartColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceSourcePortStartColumn;
    private const string ServiceSourcePortFinishColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceSourcePortFinishColumn;
    private const string ServiceDestinationPortStartColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceDestinationPortStartColumn;
    private const string ServiceDestinationPortFinishColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ServiceDestinationPortFinishColumn;
    private const string ActionColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.ActionColumn;
    private const string GroupIdColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.GroupIdColumn;
    private const string OriginalIndexColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.OriginalIndexColumn;
    private const string OriginalPolicyNameColumn = SqliteDatabaseLayout.AtomicSecurityPolicies.OriginalPolicyNameColumn;
    private const string MergeOrderIndexName = SqliteDatabaseLayout.AtomicSecurityPolicies.MergeOrderIndexName;
    private const string DefaultOrderIndexName = SqliteDatabaseLayout.AtomicSecurityPolicies.DefaultOrderIndexName;
    private const string UInt32MaximumValueLiteral = "4294967295";
    private const string ServiceCategoryMaximumValueLiteral = "2";
    private const string DestinationAddressOrderColumns =
        DestinationAddressStartColumn + ", " +
        DestinationAddressFinishColumn;
    private const string SourceAddressOrderColumns =
        SourceAddressStartColumn + ", " +
        SourceAddressFinishColumn;
    private const string ServiceOrderColumns =
        ServiceCategoryOrderColumn + ", " +
        ServiceKindColumn + ", " +
        ServiceProtocolStartColumn + ", " +
        ServiceProtocolFinishColumn + ", " +
        ServiceDestinationPortStartColumn + ", " +
        ServiceDestinationPortFinishColumn + ", " +
        ServiceSourcePortStartColumn + ", " +
        ServiceSourcePortFinishColumn;
    private const string ServiceOrderColumnsForMergeIndex =
        ServiceCategoryOrderColumn + ", " +
        ServiceProtocolStartColumn + ", " +
        ServiceProtocolFinishColumn + ", " +
        ServiceDestinationPortStartColumn + ", " +
        ServiceDestinationPortFinishColumn + ", " +
        ServiceSourcePortStartColumn + ", " +
        ServiceSourcePortFinishColumn;
    private const string CanonicalConditionOrderColumns =
        DestinationAddressOrderColumns + ", " +
        ServiceOrderColumns + ", " +
        ApplicationColumn + ", " +
        SourceAddressOrderColumns;
    private const string CanonicalConditionOrderColumnsForMerge =
        DestinationAddressOrderColumns + ", " +
        ServiceOrderColumnsForMergeIndex + ", " +
        ApplicationColumn + ", " +
        SourceAddressOrderColumns;
    private const string MergeOrderIndexColumns =
        FromZoneColumn + ", " +
        ToZoneColumn + ", " +
        ServiceKindColumn + ", " +
        OriginalIndexColumn + ", " +
        CanonicalConditionOrderColumnsForMerge + ", " +
        ActionColumn;
    private const string DefaultOrderIndexColumns =
        OriginalIndexColumn + ", " +
        FromZoneColumn + ", " +
        ToZoneColumn + ", " +
        ActionColumn + ", " +
        CanonicalConditionOrderColumns;

    private const string InitializeCommandText =
        "DROP TABLE IF EXISTS " + TableName + ";" +
        "CREATE TABLE " + TableName + " (" +
        FromZoneColumn + " TEXT NOT NULL, " +
        SourceAddressStartColumn + " INTEGER NOT NULL CHECK (" + SourceAddressStartColumn + " >= 0 AND " + SourceAddressStartColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        SourceAddressFinishColumn + " INTEGER NOT NULL CHECK (" + SourceAddressFinishColumn + " >= 0 AND " + SourceAddressFinishColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        ToZoneColumn + " TEXT NOT NULL, " +
        DestinationAddressStartColumn + " INTEGER NOT NULL CHECK (" + DestinationAddressStartColumn + " >= 0 AND " + DestinationAddressStartColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        DestinationAddressFinishColumn + " INTEGER NOT NULL CHECK (" + DestinationAddressFinishColumn + " >= 0 AND " + DestinationAddressFinishColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        ApplicationColumn + " TEXT NOT NULL, " +
        ServiceCategoryOrderColumn + " INTEGER NOT NULL CHECK (" + ServiceCategoryOrderColumn + " >= 0 AND " + ServiceCategoryOrderColumn + " <= " + ServiceCategoryMaximumValueLiteral + "), " +
        ServiceKindColumn + " TEXT NULL, " +
        ServiceProtocolStartColumn + " INTEGER NOT NULL CHECK (" + ServiceProtocolStartColumn + " >= 0 AND " + ServiceProtocolStartColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        ServiceProtocolFinishColumn + " INTEGER NOT NULL CHECK (" + ServiceProtocolFinishColumn + " >= 0 AND " + ServiceProtocolFinishColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        ServiceSourcePortStartColumn + " INTEGER NOT NULL CHECK (" + ServiceSourcePortStartColumn + " >= 0 AND " + ServiceSourcePortStartColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        ServiceSourcePortFinishColumn + " INTEGER NOT NULL CHECK (" + ServiceSourcePortFinishColumn + " >= 0 AND " + ServiceSourcePortFinishColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        ServiceDestinationPortStartColumn + " INTEGER NOT NULL CHECK (" + ServiceDestinationPortStartColumn + " >= 0 AND " + ServiceDestinationPortStartColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        ServiceDestinationPortFinishColumn + " INTEGER NOT NULL CHECK (" + ServiceDestinationPortFinishColumn + " >= 0 AND " + ServiceDestinationPortFinishColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        ActionColumn + " TEXT NOT NULL, " +
        GroupIdColumn + " TEXT NOT NULL, " +
        OriginalIndexColumn + " INTEGER NOT NULL CHECK (" + OriginalIndexColumn + " >= 0 AND " + OriginalIndexColumn + " <= " + UInt32MaximumValueLiteral + "), " +
        OriginalPolicyNameColumn + " TEXT NOT NULL" +
        ");" +
        "CREATE INDEX " + MergeOrderIndexName + " ON " + TableName + " (" + MergeOrderIndexColumns + ");" +
        "CREATE INDEX " + DefaultOrderIndexName + " ON " + TableName + " (" + DefaultOrderIndexColumns + ");";

    private const string SelectColumns =
        FromZoneColumn + ", " +
        SourceAddressStartColumn + ", " +
        SourceAddressFinishColumn + ", " +
        ToZoneColumn + ", " +
        DestinationAddressStartColumn + ", " +
        DestinationAddressFinishColumn + ", " +
        ApplicationColumn + ", " +
        ServiceKindColumn + ", " +
        ServiceProtocolStartColumn + ", " +
        ServiceProtocolFinishColumn + ", " +
        ServiceSourcePortStartColumn + ", " +
        ServiceSourcePortFinishColumn + ", " +
        ServiceDestinationPortStartColumn + ", " +
        ServiceDestinationPortFinishColumn + ", " +
        ActionColumn + ", " +
        GroupIdColumn + ", " +
        OriginalIndexColumn + ", " +
        OriginalPolicyNameColumn;

    private const string InsertColumns =
        FromZoneColumn + ", " +
        SourceAddressStartColumn + ", " +
        SourceAddressFinishColumn + ", " +
        ToZoneColumn + ", " +
        DestinationAddressStartColumn + ", " +
        DestinationAddressFinishColumn + ", " +
        ApplicationColumn + ", " +
        ServiceCategoryOrderColumn + ", " +
        ServiceKindColumn + ", " +
        ServiceProtocolStartColumn + ", " +
        ServiceProtocolFinishColumn + ", " +
        ServiceSourcePortStartColumn + ", " +
        ServiceSourcePortFinishColumn + ", " +
        ServiceDestinationPortStartColumn + ", " +
        ServiceDestinationPortFinishColumn + ", " +
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
        ServiceKindColumn + ", " +
        OriginalIndexColumn + ", " +
        CanonicalConditionOrderColumnsForMerge + ", " +
        ActionColumn + ", " +
        "rowid;";

    private const string InsertCommandText =
        "INSERT INTO " + TableName + "(" + InsertColumns + ") " +
        "VALUES ($fromZone, $sourceAddressStart, $sourceAddressFinish, $toZone, $destinationAddressStart, $destinationAddressFinish, $application, " +
        "$serviceCategoryOrder, $serviceKind, $serviceProtocolStart, $serviceProtocolFinish, $serviceSourcePortStart, $serviceSourcePortFinish, " +
        "$serviceDestinationPortStart, $serviceDestinationPortFinish, $action, $groupId, $originalIndex, $originalPolicyName);";

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
            BindInsertParameters)
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
            BindInsertParameters)
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

    private static void BindInsertParameters(SqliteCommand command, AtomicSecurityPolicy atomicPolicy)
    {
        var service = atomicPolicy.Service;
        command.Parameters.AddWithValue("$fromZone", atomicPolicy.FromZone);
        command.Parameters.AddWithValue("$sourceAddressStart", FormatUInt32(atomicPolicy.SourceAddress.Start));
        command.Parameters.AddWithValue("$sourceAddressFinish", FormatUInt32(atomicPolicy.SourceAddress.Finish));
        command.Parameters.AddWithValue("$toZone", atomicPolicy.ToZone);
        command.Parameters.AddWithValue("$destinationAddressStart", FormatUInt32(atomicPolicy.DestinationAddress.Start));
        command.Parameters.AddWithValue("$destinationAddressFinish", FormatUInt32(atomicPolicy.DestinationAddress.Finish));
        command.Parameters.AddWithValue("$application", atomicPolicy.Application);
        command.Parameters.AddWithValue("$serviceCategoryOrder", GetServiceCategoryOrder(service));
        command.Parameters.AddWithValue("$serviceKind", (object?)service.Kind ?? DBNull.Value);
        command.Parameters.AddWithValue("$serviceProtocolStart", FormatUInt32(service.ProtocolStart));
        command.Parameters.AddWithValue("$serviceProtocolFinish", FormatUInt32(service.ProtocolFinish));
        command.Parameters.AddWithValue("$serviceSourcePortStart", FormatUInt32(service.SourcePortStart));
        command.Parameters.AddWithValue("$serviceSourcePortFinish", FormatUInt32(service.SourcePortFinish));
        command.Parameters.AddWithValue("$serviceDestinationPortStart", FormatUInt32(service.DestinationPortStart));
        command.Parameters.AddWithValue("$serviceDestinationPortFinish", FormatUInt32(service.DestinationPortFinish));
        command.Parameters.AddWithValue("$action", EntityValueCodec.FormatAction(atomicPolicy.Action));
        command.Parameters.AddWithValue("$groupId", atomicPolicy.GroupId);
        command.Parameters.AddWithValue("$originalIndex", EntityValueCodec.FormatPolicyIndex(atomicPolicy.OriginalIndex));
        command.Parameters.AddWithValue("$originalPolicyName", atomicPolicy.OriginalPolicyName);
    }

    private static AtomicSecurityPolicy ReadRecord(SqliteDataReader reader)
    {
        return new AtomicSecurityPolicy
        {
            FromZone = reader.GetString(0),
            SourceAddress = new AddressValue
            {
                Start = ReadUInt32(reader, 1, SourceAddressStartColumn),
                Finish = ReadUInt32(reader, 2, SourceAddressFinishColumn)
            },
            ToZone = reader.GetString(3),
            DestinationAddress = new AddressValue
            {
                Start = ReadUInt32(reader, 4, DestinationAddressStartColumn),
                Finish = ReadUInt32(reader, 5, DestinationAddressFinishColumn)
            },
            Application = reader.GetString(6),
            Service = new ServiceValue
            {
                Kind = reader.IsDBNull(7) ? null : reader.GetString(7),
                ProtocolStart = ReadUInt32(reader, 8, ServiceProtocolStartColumn),
                ProtocolFinish = ReadUInt32(reader, 9, ServiceProtocolFinishColumn),
                SourcePortStart = ReadUInt32(reader, 10, ServiceSourcePortStartColumn),
                SourcePortFinish = ReadUInt32(reader, 11, ServiceSourcePortFinishColumn),
                DestinationPortStart = ReadUInt32(reader, 12, ServiceDestinationPortStartColumn),
                DestinationPortFinish = ReadUInt32(reader, 13, ServiceDestinationPortFinishColumn)
            },
            Action = EntityValueCodec.ParseAction(reader.GetString(14)),
            GroupId = reader.GetString(15),
            OriginalIndex = EntityValueCodec.ReadPolicyIndex(reader.GetInt64(16)),
            OriginalPolicyName = reader.GetString(17)
        };
    }

    private static long FormatUInt32(uint value)
    {
        return value;
    }

    private static uint ReadUInt32(SqliteDataReader reader, int ordinal, string columnName)
    {
        var value = reader.GetInt64(ordinal);
        if (value < 0 || value > uint.MaxValue)
        {
            throw new OverflowException($"{columnName} is out of UInt32 range: {value}");
        }

        return (uint)value;
    }

    private static int GetServiceCategoryOrder(ServiceValue service)
    {
        if (IsAnyService(service))
        {
            return 0;
        }

        return string.IsNullOrWhiteSpace(service.Kind) ? 2 : 1;
    }

    private static bool IsAnyService(ServiceValue service)
    {
        return service.Kind is null
            && service.ProtocolStart == 0
            && service.ProtocolFinish == 255
            && service.SourcePortStart == 0
            && service.SourcePortFinish == 65535
            && service.DestinationPortStart == 0
            && service.DestinationPortFinish == 65535;
    }
}
