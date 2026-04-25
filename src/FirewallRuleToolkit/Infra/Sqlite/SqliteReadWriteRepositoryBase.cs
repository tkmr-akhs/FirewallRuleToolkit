using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Infra.Sqlite;

/// <summary>
/// SQLite の read/write リポジトリ実装の基底クラスです。
/// </summary>
/// <typeparam name="T">永続化対象の型。</typeparam>
public abstract class SqliteReadWriteRepositoryBase<T> : IReadWriteRepository<T>, IItemCountRepository
{
    private const string CountCommandTextPrefix = "SELECT COUNT(*) FROM ";
    private const string CountCommandTextSuffix = ";";

    private readonly string initializeCommandText;
    private readonly string selectCommandText;
    private readonly string insertCommandText;
    private readonly string countCommandText;
    private readonly Func<SqliteDataReader, T> readRecord;
    private readonly Action<SqliteCommand, T> bindInsertParameters;
    private readonly SqliteWriteTransaction? writeTransaction;

    /// <summary>
    /// SQLite の read/write リポジトリ実装の基底クラスのコンストラクターです。
    /// </summary>
    /// <param name="databaseDirectory">SQLite データベース ディレクトリ。</param>
    /// <param name="tableName">件数取得対象のテーブル名。</param>
    /// <param name="initializeCommandText">保存先を初期化する SQL。</param>
    /// <param name="selectCommandText">全件取得する SQL。</param>
    /// <param name="insertCommandText">1 件挿入する SQL。</param>
    /// <param name="readRecord">読み取り行からエンティティへ変換する関数。</param>
    /// <param name="bindInsertParameters">挿入コマンドへエンティティをバインドする関数。</param>
    protected SqliteReadWriteRepositoryBase(
        string databaseDirectory,
        string tableName,
        string initializeCommandText,
        string selectCommandText,
        string insertCommandText,
        Func<SqliteDataReader, T> readRecord,
        Action<SqliteCommand, T> bindInsertParameters)
        : this(
            SqliteRepositoryHelper.ResolveDatabasePath(
                databaseDirectory,
                SqliteDatabaseLayout.DatabaseFileName),
            null,
            tableName,
            initializeCommandText,
            selectCommandText,
            insertCommandText,
            readRecord,
            bindInsertParameters)
    {
    }

    private protected SqliteReadWriteRepositoryBase(
        SqliteWriteTransaction writeTransaction,
        string tableName,
        string initializeCommandText,
        string selectCommandText,
        string insertCommandText,
        Func<SqliteDataReader, T> readRecord,
        Action<SqliteCommand, T> bindInsertParameters)
        : this(
            (writeTransaction ?? throw new ArgumentNullException(nameof(writeTransaction))).DatabasePath,
            writeTransaction,
            tableName,
            initializeCommandText,
            selectCommandText,
            insertCommandText,
            readRecord,
            bindInsertParameters)
    {
    }

    private SqliteReadWriteRepositoryBase(
        string databasePath,
        SqliteWriteTransaction? writeTransaction,
        string tableName,
        string initializeCommandText,
        string selectCommandText,
        string insertCommandText,
        Func<SqliteDataReader, T> readRecord,
        Action<SqliteCommand, T> bindInsertParameters)
    {
        DatabasePath = databasePath ?? throw new ArgumentNullException(nameof(databasePath));
        this.writeTransaction = writeTransaction;
        countCommandText = CountCommandTextPrefix + (tableName ?? throw new ArgumentNullException(nameof(tableName))) + CountCommandTextSuffix;
        this.initializeCommandText = initializeCommandText ?? throw new ArgumentNullException(nameof(initializeCommandText));
        this.selectCommandText = selectCommandText ?? throw new ArgumentNullException(nameof(selectCommandText));
        this.insertCommandText = insertCommandText ?? throw new ArgumentNullException(nameof(insertCommandText));
        this.readRecord = readRecord ?? throw new ArgumentNullException(nameof(readRecord));
        this.bindInsertParameters = bindInsertParameters ?? throw new ArgumentNullException(nameof(bindInsertParameters));
    }

    /// <summary>
    /// SQLite データベース ファイル パスを取得します。
    /// </summary>
    public string DatabasePath { get; }

    /// <inheritdoc />
    public virtual void EnsureAvailable()
    {
        // 読み取り可否の詳細検証が必要な実装だけ具象クラス側で追加確認します。
    }

    /// <inheritdoc />
    public int Count()
    {
        if (writeTransaction is not null)
        {
            using var transactionCommand = writeTransaction.Connection.CreateCommand();
            transactionCommand.Transaction = writeTransaction.Transaction;
            transactionCommand.CommandText = countCommandText;

            return Convert.ToInt32(transactionCommand.ExecuteScalar());
        }

        using var connection = SqliteRepositoryHelper.OpenConnection(DatabasePath);
        using var command = connection.CreateCommand();
        command.CommandText = countCommandText;

        return Convert.ToInt32(command.ExecuteScalar());
    }

    /// <inheritdoc />
    public IEnumerable<T> GetAll()
    {
        if (writeTransaction is not null)
        {
            using var transactionCommand = writeTransaction.Connection.CreateCommand();
            transactionCommand.Transaction = writeTransaction.Transaction;
            transactionCommand.CommandText = selectCommandText;

            using var transactionReader = transactionCommand.ExecuteReader();
            while (transactionReader.Read())
            {
                yield return readRecord(transactionReader);
            }

            yield break;
        }

        using var connection = SqliteRepositoryHelper.OpenConnection(DatabasePath);
        using var command = connection.CreateCommand();
        command.CommandText = selectCommandText;

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            yield return readRecord(reader);
        }
    }

    /// <inheritdoc />
    public void Initialize()
    {
        ExecuteWrite((connection, transaction) =>
            SqliteRepositoryHelper.ExecuteNonQuery(connection, transaction, initializeCommandText));
    }

    /// <inheritdoc />
    public void AppendRange(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        ExecuteWrite((connection, transaction) => ExecuteInsertBatch(connection, transaction, items));
    }

    /// <inheritdoc />
    public void ReplaceAll(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        ExecuteWrite((connection, transaction) =>
        {
            SqliteRepositoryHelper.ExecuteNonQuery(connection, transaction, initializeCommandText);
            ExecuteInsertBatch(connection, transaction, items);
        });
    }

    /// <summary>
    /// 書き込み完了時に呼ばれます。SQLite 実装ではトランザクション側で確定します。
    /// </summary>
    public void Complete()
    {
    }

    private void ExecuteWrite(Action<SqliteConnection, SqliteTransaction> action)
    {
        ArgumentNullException.ThrowIfNull(action);

        if (writeTransaction is not null)
        {
            action(writeTransaction.Connection, writeTransaction.Transaction);
            return;
        }

        using var connection = SqliteRepositoryHelper.OpenConnection(DatabasePath, createDirectory: true);
        using var transaction = connection.BeginTransaction();
        action(connection, transaction);
        transaction.Commit();
    }

    private void ExecuteInsertBatch(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IEnumerable<T> items)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = insertCommandText;

        foreach (var item in items)
        {
            command.Parameters.Clear();
            bindInsertParameters(command, item);
            command.ExecuteNonQuery();
        }
    }

}
