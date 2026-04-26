namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// 名前付きサービス定義を SQLite で読み書きします。
/// </summary>
public sealed class SqliteServiceDefinitionRepository : SqliteReadWriteRepositoryBase<ServiceDefinition>
{
    private const string TableName = SqliteDatabaseLayout.ServiceDefinitions.TableName;
    private const string NameColumn = SqliteDatabaseLayout.ServiceDefinitions.NameColumn;
    private const string ProtocolColumn = SqliteDatabaseLayout.ServiceDefinitions.ProtocolColumn;
    private const string SourcePortColumn = SqliteDatabaseLayout.ServiceDefinitions.SourcePortColumn;
    private const string DestinationPortColumn = SqliteDatabaseLayout.ServiceDefinitions.DestinationPortColumn;
    private const string KindColumn = SqliteDatabaseLayout.ServiceDefinitions.KindColumn;

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
    /// 名前付きサービス定義を SQLite で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    public SqliteServiceDefinitionRepository(string databaseDirectory)
        : base(
            databaseDirectory,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new ServiceDefinition
            {
                Name = reader.GetString(0),
                Protocol = reader.GetString(1),
                SourcePort = reader.GetString(2),
                DestinationPort = reader.GetString(3),
                Kind = reader.IsDBNull(4) ? null : reader.GetString(4)
            },
            static (command, serviceDefinition) =>
            {
                command.Parameters.AddWithValue("$name", serviceDefinition.Name);
                command.Parameters.AddWithValue("$protocol", serviceDefinition.Protocol);
                command.Parameters.AddWithValue("$sourcePort", serviceDefinition.SourcePort);
                command.Parameters.AddWithValue("$destinationPort", serviceDefinition.DestinationPort);
                command.Parameters.AddWithValue("$kind", (object?)serviceDefinition.Kind ?? DBNull.Value);
            })
    {
    }

    internal SqliteServiceDefinitionRepository(SqliteWriteTransaction writeTransaction)
        : base(
            writeTransaction,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new ServiceDefinition
            {
                Name = reader.GetString(0),
                Protocol = reader.GetString(1),
                SourcePort = reader.GetString(2),
                DestinationPort = reader.GetString(3),
                Kind = reader.IsDBNull(4) ? null : reader.GetString(4)
            },
            static (command, serviceDefinition) =>
            {
                command.Parameters.AddWithValue("$name", serviceDefinition.Name);
                command.Parameters.AddWithValue("$protocol", serviceDefinition.Protocol);
                command.Parameters.AddWithValue("$sourcePort", serviceDefinition.SourcePort);
                command.Parameters.AddWithValue("$destinationPort", serviceDefinition.DestinationPort);
                command.Parameters.AddWithValue("$kind", (object?)serviceDefinition.Kind ?? DBNull.Value);
            })
    {
    }

    /// <inheritdoc />
    public override void EnsureAvailable()
    {
        SqliteRepositoryHelper.EnsureTableAvailable(
            DatabasePath,
            TableName,
            "Service definitions are unavailable. Run import before lookup.");
    }

}
