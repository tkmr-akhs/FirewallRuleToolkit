namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// 名前付きアドレス定義を SQLite で読み書きします。
/// </summary>
public sealed class SqliteAddressDefinitionRepository : SqliteReadWriteRepositoryBase<AddressDefinition>
{
    private const string TableName = SqliteDatabaseLayout.AddressDefinitions.TableName;
    private const string NameColumn = SqliteDatabaseLayout.AddressDefinitions.NameColumn;
    private const string ValueColumn = SqliteDatabaseLayout.AddressDefinitions.ValueColumn;

    private const string InitializeCommandText =
        "CREATE TABLE IF NOT EXISTS " + TableName + " (" +
        NameColumn + " TEXT NOT NULL PRIMARY KEY, " +
        ValueColumn + " TEXT NOT NULL" +
        ");" +
        "DELETE FROM " + TableName + ";";

    private const string SelectAllCommandText =
        "SELECT " + NameColumn + ", " + ValueColumn +
        " FROM " + TableName +
        " ORDER BY " + NameColumn + ";";

    private const string InsertCommandText =
        "INSERT INTO " + TableName + "(" + NameColumn + ", " + ValueColumn + ") " +
        "VALUES ($name, $value);";

    /// <summary>
    /// 名前付きアドレス定義を SQLite で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    public SqliteAddressDefinitionRepository(string databaseDirectory)
        : base(
            databaseDirectory,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new AddressDefinition
            {
                Name = reader.GetString(0),
                Value = reader.GetString(1)
            },
            static (command, addressDefinition) =>
            {
                command.Parameters.AddWithValue("$name", addressDefinition.Name);
                command.Parameters.AddWithValue("$value", addressDefinition.Value);
            })
    {
    }

    internal SqliteAddressDefinitionRepository(SqliteWriteTransaction writeTransaction)
        : base(
            writeTransaction,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new AddressDefinition
            {
                Name = reader.GetString(0),
                Value = reader.GetString(1)
            },
            static (command, addressDefinition) =>
            {
                command.Parameters.AddWithValue("$name", addressDefinition.Name);
                command.Parameters.AddWithValue("$value", addressDefinition.Value);
            })
    {
    }

    /// <inheritdoc />
    public override void EnsureAvailable()
    {
        SqliteRepositoryHelper.EnsureTableAvailable(
            DatabasePath,
            TableName,
            "Address definitions are unavailable. Run import before lookup.");
    }

}
