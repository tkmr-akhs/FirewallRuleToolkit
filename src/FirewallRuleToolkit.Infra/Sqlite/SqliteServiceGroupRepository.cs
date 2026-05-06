namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// サービス グループを SQLite で読み書きします。
/// </summary>
public sealed class SqliteServiceGroupRepository : SqliteReadWriteRepositoryBase<ServiceGroupMembership>
{
    private const string TableName = SqliteDatabaseLayout.ServiceGroupMembers.TableName;
    private const string GroupNameColumn = SqliteDatabaseLayout.ServiceGroupMembers.GroupNameColumn;
    private const string MemberNameColumn = SqliteDatabaseLayout.ServiceGroupMembers.MemberNameColumn;
    private const string GroupNameIndexName = SqliteDatabaseLayout.ServiceGroupMembers.GroupNameIndexName;

    private const string InitializeCommandText =
        "CREATE TABLE IF NOT EXISTS " + TableName + " (" +
        GroupNameColumn + " TEXT NOT NULL, " +
        MemberNameColumn + " TEXT NOT NULL" +
        ");" +
        "CREATE INDEX IF NOT EXISTS " + GroupNameIndexName +
        " ON " + TableName + "(" + GroupNameColumn + ");" +
        "DELETE FROM " + TableName + ";";

    private const string SelectAllCommandText =
        "SELECT " + GroupNameColumn + ", " + MemberNameColumn +
        " FROM " + TableName +
        " ORDER BY " + GroupNameColumn + ", rowid;";

    private const string InsertCommandText =
        "INSERT INTO " + TableName + "(" + GroupNameColumn + ", " + MemberNameColumn + ") " +
        "VALUES ($groupName, $memberName);";

    /// <summary>
    /// サービス グループを SQLite で読み書きするクラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    public SqliteServiceGroupRepository(string databaseDirectory)
        : base(
            databaseDirectory,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new ServiceGroupMembership
            {
                GroupName = reader.GetString(0),
                MemberName = reader.GetString(1)
            },
            static (command, member) =>
            {
                command.Parameters.AddWithValue("$groupName", member.GroupName);
                command.Parameters.AddWithValue("$memberName", member.MemberName);
            })
    {
    }

    internal SqliteServiceGroupRepository(SqliteWriteTransaction writeTransaction)
        : base(
            writeTransaction,
            TableName,
            InitializeCommandText,
            SelectAllCommandText,
            InsertCommandText,
            static reader => new ServiceGroupMembership
            {
                GroupName = reader.GetString(0),
                MemberName = reader.GetString(1)
            },
            static (command, member) =>
            {
                command.Parameters.AddWithValue("$groupName", member.GroupName);
                command.Parameters.AddWithValue("$memberName", member.MemberName);
            })
    {
    }

    /// <inheritdoc />
    public override void EnsureAvailable()
    {
        SqliteRepositoryHelper.EnsureTableAvailable(
            DatabasePath,
            TableName,
            "Service groups are unavailable. Run import before lookup.");
    }

}
