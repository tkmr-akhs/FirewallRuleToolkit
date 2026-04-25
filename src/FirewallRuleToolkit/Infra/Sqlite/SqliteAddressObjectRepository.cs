namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// アドレス オブジェクトを SQLite で読み書きします。
/// </summary>
public sealed class SqliteAddressObjectRepository : SqliteReadWriteRepositoryBase<AddressObject>
{
    private const string TableName = SqliteDatabaseLayout.AddressObjects.TableName;
    private const string NameColumn = SqliteDatabaseLayout.AddressObjects.NameColumn;
    private const string ValueColumn = SqliteDatabaseLayout.AddressObjects.ValueColumn;

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
    /// アドレス オブジェクトを SQLite で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    public SqliteAddressObjectRepository(string databaseDirectory)
        : base(
            databaseDirectory,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new AddressObject
            {
                Name = reader.GetString(0),
                Value = reader.GetString(1)
            },
            static (command, addressObject) =>
            {
                command.Parameters.AddWithValue("$name", addressObject.Name);
                command.Parameters.AddWithValue("$value", addressObject.Value);
            })
    {
    }

    internal SqliteAddressObjectRepository(SqliteWriteTransaction writeTransaction)
        : base(
            writeTransaction,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new AddressObject
            {
                Name = reader.GetString(0),
                Value = reader.GetString(1)
            },
            static (command, addressObject) =>
            {
                command.Parameters.AddWithValue("$name", addressObject.Name);
                command.Parameters.AddWithValue("$value", addressObject.Value);
            })
    {
    }

    /// <inheritdoc />
    public override void EnsureAvailable()
    {
        SqliteRepositoryHelper.EnsureTableAvailable(
            DatabasePath,
            TableName,
            "Address objects are unavailable. Run import before lookup.");
    }

}
