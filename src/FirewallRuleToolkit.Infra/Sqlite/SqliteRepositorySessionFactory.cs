namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// SQLite repository の書き込みセッションを開始します。
/// </summary>
public sealed class SqliteRepositorySessionFactory : IWriteRepositorySessionFactory
{
    private readonly string databaseDirectory;

    /// <summary>
    /// SQLite repository の書き込みセッションを開始するファクトリのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">データベース ディレクトリ。</param>
    public SqliteRepositorySessionFactory(string databaseDirectory)
    {
        this.databaseDirectory = databaseDirectory;
    }

    /// <inheritdoc />
    public IWriteRepositorySession BeginWriteSession()
    {
        return new SqliteRepositorySession(SqliteWriteTransaction.Begin(databaseDirectory));
    }
}
