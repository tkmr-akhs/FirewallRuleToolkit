namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// SQLite repository の書き込みセッションを開始します。
/// </summary>
internal sealed class SqliteRepositorySessionFactory : IWriteRepositorySessionFactory
{
    private readonly string databaseDirectory;

    public SqliteRepositorySessionFactory(string databaseDirectory)
    {
        this.databaseDirectory = databaseDirectory;
    }

    public IWriteRepositorySession BeginWriteSession()
    {
        return new SqliteRepositorySession(SqliteWriteTransaction.Begin(databaseDirectory));
    }
}
