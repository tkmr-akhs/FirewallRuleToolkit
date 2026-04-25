using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// 単一 SQLite ファイルへの書き込みを 1 トランザクションで扱います。
/// </summary>
internal sealed class SqliteWriteTransaction : IDisposable
{
    private readonly SqliteConnection connection;
    private readonly SqliteTransaction transaction;
    private bool committed;
    private bool disposed;

    private SqliteWriteTransaction(
        string databasePath,
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        DatabasePath = databasePath;
        this.connection = connection;
        this.transaction = transaction;
    }

    public string DatabasePath { get; }

    internal SqliteConnection Connection => connection;

    internal SqliteTransaction Transaction => transaction;

    public static SqliteWriteTransaction Begin(string databaseDirectory)
    {
        var databasePath = SqliteRepositoryHelper.ResolveDatabasePath(
            databaseDirectory,
            SqliteDatabaseLayout.DatabaseFileName);
        var connection = SqliteRepositoryHelper.OpenConnection(databasePath, createDirectory: true);
        var transaction = connection.BeginTransaction();

        return new SqliteWriteTransaction(databasePath, connection, transaction);
    }

    public void Commit()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if (committed)
        {
            return;
        }

        transaction.Commit();
        committed = true;
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;

        if (!committed)
        {
            try
            {
                transaction.Rollback();
            }
            catch (InvalidOperationException)
            {
            }
            catch (SqliteException)
            {
            }
        }

        transaction.Dispose();
        connection.Dispose();
    }
}
