namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// サービス オブジェクトを SQLite で読み書きします。
/// </summary>
public sealed class SqliteServiceObjectRepository : SqliteReadWriteRepositoryBase<ServiceObject>
{
    private const string TableName = SqliteDatabaseLayout.ServiceObjects.TableName;
    private const string NameColumn = SqliteDatabaseLayout.ServiceObjects.NameColumn;
    private const string ProtocolColumn = SqliteDatabaseLayout.ServiceObjects.ProtocolColumn;
    private const string SourcePortColumn = SqliteDatabaseLayout.ServiceObjects.SourcePortColumn;
    private const string DestinationPortColumn = SqliteDatabaseLayout.ServiceObjects.DestinationPortColumn;
    private const string KindColumn = SqliteDatabaseLayout.ServiceObjects.KindColumn;

    private const string InitializeCommandText =
        "DROP TABLE IF EXISTS " + TableName + ";" +
        "CREATE TABLE " + TableName + " (" +
        NameColumn + " TEXT NOT NULL PRIMARY KEY, " +
        ProtocolColumn + " TEXT NOT NULL, " +
        SourcePortColumn + " TEXT NOT NULL, " +
        DestinationPortColumn + " TEXT NOT NULL, " +
        KindColumn + " TEXT NULL" +
        ");";

    private const string SelectAllCommandText =
        "SELECT " + NameColumn + ", " + ProtocolColumn + ", " + SourcePortColumn + ", " + DestinationPortColumn + ", " + KindColumn +
        " FROM " + TableName +
        " ORDER BY " + NameColumn + ";";

    private const string InsertCommandText =
        "INSERT INTO " + TableName + "(" + NameColumn + ", " + ProtocolColumn + ", " + SourcePortColumn + ", " + DestinationPortColumn + ", " + KindColumn + ") " +
        "VALUES ($name, $protocol, $sourcePort, $destinationPort, $kind);";

    /// <summary>
    /// サービス オブジェクトを SQLite で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    public SqliteServiceObjectRepository(string databaseDirectory)
        : base(
            databaseDirectory,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new ServiceObject
            {
                Name = reader.GetString(0),
                Protocol = reader.GetString(1),
                SourcePort = reader.GetString(2),
                DestinationPort = reader.GetString(3),
                Kind = reader.IsDBNull(4) ? null : reader.GetString(4)
            },
            static (command, serviceObject) =>
            {
                command.Parameters.AddWithValue("$name", serviceObject.Name);
                command.Parameters.AddWithValue("$protocol", serviceObject.Protocol);
                command.Parameters.AddWithValue("$sourcePort", serviceObject.SourcePort);
                command.Parameters.AddWithValue("$destinationPort", serviceObject.DestinationPort);
                command.Parameters.AddWithValue("$kind", (object?)serviceObject.Kind ?? DBNull.Value);
            })
    {
    }

    internal SqliteServiceObjectRepository(SqliteWriteTransaction writeTransaction)
        : base(
            writeTransaction,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new ServiceObject
            {
                Name = reader.GetString(0),
                Protocol = reader.GetString(1),
                SourcePort = reader.GetString(2),
                DestinationPort = reader.GetString(3),
                Kind = reader.IsDBNull(4) ? null : reader.GetString(4)
            },
            static (command, serviceObject) =>
            {
                command.Parameters.AddWithValue("$name", serviceObject.Name);
                command.Parameters.AddWithValue("$protocol", serviceObject.Protocol);
                command.Parameters.AddWithValue("$sourcePort", serviceObject.SourcePort);
                command.Parameters.AddWithValue("$destinationPort", serviceObject.DestinationPort);
                command.Parameters.AddWithValue("$kind", (object?)serviceObject.Kind ?? DBNull.Value);
            })
    {
    }

    /// <inheritdoc />
    public override void EnsureAvailable()
    {
        SqliteRepositoryHelper.EnsureTableAvailable(
            DatabasePath,
            TableName,
            "Service objects are unavailable. Run import before lookup.");
    }

}
