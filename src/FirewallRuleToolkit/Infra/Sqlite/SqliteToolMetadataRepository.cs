using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// ツール実行メタデータを SQLite で読み書きします。
/// </summary>
public sealed class SqliteToolMetadataRepository : IToolMetadataRepository
{
    private const string TableName = SqliteDatabaseLayout.ToolMetadata.TableName;
    private const string KeyColumn = SqliteDatabaseLayout.ToolMetadata.KeyColumn;
    private const string ValueColumn = SqliteDatabaseLayout.ToolMetadata.ValueColumn;

    private const string InitializeCommandText =
        "CREATE TABLE IF NOT EXISTS " + TableName + " (" +
        KeyColumn + " TEXT NOT NULL PRIMARY KEY, " +
        ValueColumn + " TEXT NOT NULL" +
        ");";

    private const string DeleteAllCommandText =
        "DELETE FROM " + TableName + ";";

    private const string UpsertCommandText =
        "INSERT INTO " + TableName + "(" + KeyColumn + ", " + ValueColumn + ") " +
        "VALUES ($key, $value) " +
        "ON CONFLICT(" + KeyColumn + ") DO UPDATE SET " + ValueColumn + " = excluded." + ValueColumn + ";";

    private const string SelectByKeyCommandText =
        "SELECT " + ValueColumn +
        " FROM " + TableName +
        " WHERE " + KeyColumn + " = $key;";

    private const string AtomizeThresholdKey = "atomize.threshold";

    private readonly string databasePath;
    private readonly SqliteWriteTransaction? writeTransaction;

    /// <summary>
    /// ツール実行メタデータを SQLite で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    public SqliteToolMetadataRepository(string databaseDirectory)
    {
        databasePath = SqliteRepositoryHelper.ResolveDatabasePath(
            databaseDirectory,
            SqliteDatabaseLayout.DatabaseFileName);
    }

    internal SqliteToolMetadataRepository(SqliteWriteTransaction writeTransaction)
    {
        this.writeTransaction = writeTransaction ?? throw new ArgumentNullException(nameof(writeTransaction));
        databasePath = writeTransaction.DatabasePath;
    }

    /// <inheritdoc />
    public void EnsureAvailable()
    {
        SqliteRepositoryHelper.EnsureTableAvailable(
            databasePath,
            TableName,
            "Tool metadata is unavailable. Run atomize before export.");
    }

    /// <inheritdoc />
    public void SetAtomizeThreshold(int threshold)
    {
        if (threshold <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(threshold), threshold, "Threshold must be greater than zero.");
        }

        ExecuteWrite((connection, transaction) =>
        {
            SqliteRepositoryHelper.ExecuteNonQuery(connection, transaction, InitializeCommandText);

            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = UpsertCommandText;
            command.Parameters.AddWithValue("$key", AtomizeThresholdKey);
            command.Parameters.AddWithValue("$value", threshold.ToString());
            command.ExecuteNonQuery();
        });
    }

    /// <inheritdoc />
    public bool TryGetAtomizeThreshold(out int threshold)
    {
        if (!TryGetValue(AtomizeThresholdKey, out var value)
            || !int.TryParse(value, out threshold)
            || threshold <= 0)
        {
            threshold = default;
            return false;
        }

        return true;
    }

    /// <inheritdoc />
    public void Clear()
    {
        ExecuteWrite((connection, transaction) =>
        {
            SqliteRepositoryHelper.ExecuteNonQuery(connection, transaction, InitializeCommandText);
            SqliteRepositoryHelper.ExecuteNonQuery(connection, transaction, DeleteAllCommandText);
        });
    }

    private bool TryGetValue(string key, out string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        value = string.Empty;
        if (writeTransaction is not null)
        {
            using var transactionCommand = writeTransaction.Connection.CreateCommand();
            transactionCommand.Transaction = writeTransaction.Transaction;
            transactionCommand.CommandText = SelectByKeyCommandText;
            transactionCommand.Parameters.AddWithValue("$key", key);
            var scalar = transactionCommand.ExecuteScalar();
            if (scalar is null)
            {
                return false;
            }

            value = scalar.ToString() ?? string.Empty;
            return true;
        }

        if (!File.Exists(databasePath))
        {
            return false;
        }

        try
        {
            using var connection = SqliteRepositoryHelper.OpenConnection(databasePath);
            using var command = connection.CreateCommand();
            command.CommandText = SelectByKeyCommandText;
            command.Parameters.AddWithValue("$key", key);
            var scalar = command.ExecuteScalar();
            if (scalar is null)
            {
                return false;
            }

            value = scalar.ToString() ?? string.Empty;
            return true;
        }
        catch (SqliteException)
        {
            return false;
        }
    }

    private void ExecuteWrite(Action<SqliteConnection, SqliteTransaction> action)
    {
        ArgumentNullException.ThrowIfNull(action);

        if (writeTransaction is not null)
        {
            action(writeTransaction.Connection, writeTransaction.Transaction);
            return;
        }

        using var connection = SqliteRepositoryHelper.OpenConnection(databasePath, createDirectory: true);
        using var transaction = connection.BeginTransaction();
        action(connection, transaction);
        transaction.Commit();
    }
}
