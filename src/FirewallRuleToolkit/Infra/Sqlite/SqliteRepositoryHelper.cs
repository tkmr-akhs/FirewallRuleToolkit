using Microsoft.Data.Sqlite;

using FirewallRuleToolkit.Domain;

namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// SQLite ストア実装の共通処理を提供します。
/// </summary>
internal static class SqliteRepositoryHelper
{
    /// <summary>
    /// データベース ディレクトリとファイル名から SQLite パスを解決します。
    /// </summary>
    /// <param name="databaseDirectory">データベース ディレクトリ。</param>
    /// <param name="databaseFileName">データベース ファイル名。</param>
    /// <returns>解決済み SQLite パス。</returns>
    public static string ResolveDatabasePath(string databaseDirectory, string databaseFileName)
    {
        if (string.IsNullOrWhiteSpace(databaseDirectory))
        {
            throw new ArgumentException("Database directory is required.", nameof(databaseDirectory));
        }

        if (string.IsNullOrWhiteSpace(databaseFileName))
        {
            throw new ArgumentException("Database file name is required.", nameof(databaseFileName));
        }

        if (Path.GetExtension(databaseDirectory).Equals(".sqlite", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Database must be a directory path, not a .sqlite file path.", nameof(databaseDirectory));
        }

        return Path.Combine(Path.GetFullPath(databaseDirectory), databaseFileName);
    }

    /// <summary>
    /// SQLite 接続を開きます。
    /// </summary>
    /// <param name="databasePath">SQLite データベース パス。</param>
    /// <param name="createDirectory">必要に応じて親ディレクトリを作成する場合は <see langword="true"/>。</param>
    /// <returns>開かれた SQLite 接続。</returns>
    public static SqliteConnection OpenConnection(string databasePath, bool createDirectory = false)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            throw new ArgumentException("Database path is required.", nameof(databasePath));
        }

        if (createDirectory)
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(databasePath));
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }

        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath
        }.ToString();
        var connection = new SqliteConnection(connectionString);
        connection.Open();

        if (createDirectory)
        {
            EnableWriteAheadLog(connection);
        }

        return connection;
    }

    private static void EnableWriteAheadLog(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL;";

        var journalMode = command.ExecuteScalar()?.ToString();
        if (!string.Equals(journalMode, "wal", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"SQLite journal mode could not be set to WAL. actual: {journalMode}");
        }
    }

    /// <summary>
    /// SQL をトランザクション内で実行します。
    /// </summary>
    /// <param name="connection">実行に使用する接続。</param>
    /// <param name="transaction">実行に使用するトランザクション。</param>
    /// <param name="commandText">実行する SQL。</param>
    public static void ExecuteNonQuery(SqliteConnection connection, SqliteTransaction transaction, string commandText)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = commandText;
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// 指定テーブルが利用可能であることを確認します。
    /// </summary>
    /// <param name="databasePath">SQLite データベース パス。</param>
    /// <param name="tableName">確認対象テーブル名。</param>
    /// <param name="unavailableMessage">利用不可時の例外メッセージ。</param>
    /// <param name="requireExistingFile">事前に DB ファイルの存在を要求する場合は <see langword="true"/>。</param>
    public static void EnsureTableAvailable(
        string databasePath,
        string tableName,
        string unavailableMessage,
        bool requireExistingFile = true)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            throw new ArgumentException("Database path is required.", nameof(databasePath));
        }

        if (string.IsNullOrWhiteSpace(tableName))
        {
            throw new ArgumentException("Table name is required.", nameof(tableName));
        }

        if (string.IsNullOrWhiteSpace(unavailableMessage))
        {
            throw new ArgumentException("Unavailable message is required.", nameof(unavailableMessage));
        }

        if (requireExistingFile && !File.Exists(databasePath))
        {
            throw new RepositoryUnavailableException(unavailableMessage);
        }

        try
        {
            using var connection = OpenConnection(databasePath);
            using var command = connection.CreateCommand();
            command.CommandText =
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $tableName LIMIT 1;";
            command.Parameters.AddWithValue("$tableName", tableName);

            if (command.ExecuteScalar() is null)
            {
                throw new RepositoryUnavailableException(unavailableMessage);
            }
        }
        catch (SqliteException ex)
        {
            throw new RepositoryUnavailableException(unavailableMessage, ex);
        }
    }
}

