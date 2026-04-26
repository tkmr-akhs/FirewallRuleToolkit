using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.Exceptions;
using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.ValueObjects;
using FirewallRuleToolkit.Infra.Sqlite;
using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Tests.Infra.Sqlite;

public sealed class SqliteRepositorySessionTests
{
    [Fact]
    public void Commit_PublishesAllTablesInSingleDatabase()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            IWriteRepositorySessionFactory sessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);

            using (var writeSession = sessionFactory.BeginWriteSession())
            {
                writeSession.AddressObjects.ReplaceAll(
                [
                    new AddressObject
                    {
                        Name = "host-a",
                        Value = "192.168.1.10/32"
                    }
                ]);
                writeSession.AddressGroups.ReplaceAll(
                [
                    new AddressGroupMembership
                    {
                        GroupName = "src-group",
                        MemberName = "host-a"
                    }
                ]);
                writeSession.ImportedSecurityPolicies.ReplaceAll([CreateImportedPolicy()]);
                writeSession.ToolMetadata.SetAtomizeThreshold(7);

                writeSession.Commit();
            }

            var databasePath = Path.Combine(databaseDirectory, SqliteDatabaseLayout.DatabaseFileName);
            Assert.True(File.Exists(databasePath));
            Assert.Equal(["host-a"], new SqliteAddressObjectRepository(databaseDirectory).GetAll().Select(static item => item.Name));
            Assert.Equal(["src-group"], new SqliteAddressGroupRepository(databaseDirectory).GetAll().Select(static item => item.GroupName));
            Assert.Equal(["allow-web"], new SqliteImportedSecurityPolicyRepository(databaseDirectory).GetAll().Select(static item => item.Name));
            var metadata = new SqliteToolMetadataRepository(databaseDirectory);
            Assert.True(metadata.TryGetAtomizeThreshold(out var threshold));
            Assert.Equal(7, threshold);
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void DisposeWithoutCommit_RollsBackAllWrites()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            IWriteRepositorySessionFactory sessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);

            using (var writeSession = sessionFactory.BeginWriteSession())
            {
                writeSession.AddressObjects.ReplaceAll(
                [
                    new AddressObject
                    {
                        Name = "host-a",
                        Value = "192.168.1.10/32"
                    }
                ]);
                writeSession.ImportedSecurityPolicies.ReplaceAll([CreateImportedPolicy()]);
                writeSession.ToolMetadata.SetAtomizeThreshold(7);
            }

            Assert.Throws<RepositoryUnavailableException>(new SqliteAddressObjectRepository(databaseDirectory).EnsureAvailable);
            Assert.Throws<RepositoryUnavailableException>(new SqliteImportedSecurityPolicyRepository(databaseDirectory).EnsureAvailable);
            Assert.False(new SqliteToolMetadataRepository(databaseDirectory).TryGetAtomizeThreshold(out _));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void DisposeWithoutCommit_KeepsPreviousCommittedSnapshot()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var publishedRepository = new SqliteAddressObjectRepository(databaseDirectory);
            publishedRepository.ReplaceAll(
            [
                new AddressObject
                {
                    Name = "published",
                    Value = "192.168.1.10/32"
                }
            ]);

            IWriteRepositorySessionFactory sessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);

            using (var writeSession = sessionFactory.BeginWriteSession())
            {
                writeSession.AddressObjects.ReplaceAll(
                [
                    new AddressObject
                    {
                        Name = "pending",
                        Value = "192.168.1.20/32"
                    }
                ]);
            }

            Assert.Equal(["published"], publishedRepository.GetAll().Select(static item => item.Name));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void BeginWriteSession_EnablesWalJournalMode()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            CreateAddressObjectDatabaseInRollbackJournalMode(databaseDirectory);

            IWriteRepositorySessionFactory sessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);

            using (sessionFactory.BeginWriteSession())
            {
            }

            Assert.Equal("wal", ReadJournalMode(databaseDirectory));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void ActiveWriteSession_AllowsReadsFromSeparateConnection()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            CreateAddressObjectDatabaseInRollbackJournalMode(databaseDirectory);
            IWriteRepositorySessionFactory sessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);

            using var writeSession = sessionFactory.BeginWriteSession();
            writeSession.AtomicPolicies.Initialize();
            writeSession.AtomicPolicies.AppendRange([CreateAtomicPolicy(10, "pending")]);

            var values = new SqliteAddressObjectRepository(databaseDirectory)
                .GetAll()
                .Select(static item => item.Value)
                .ToArray();

            Assert.Equal(["192.168.1.10/32"], values);
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void OpenConnection_AllowsDatabasePathContainingSemicolon()
    {
        var databaseDirectory = CreateTempDatabaseDirectory() + ";semi";
        var databasePath = Path.Combine(databaseDirectory, SqliteDatabaseLayout.DatabaseFileName);

        try
        {
            using var connection = SqliteRepositoryHelper.OpenConnection(databasePath, createDirectory: true);
            using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE sample (id INTEGER NOT NULL);";
            command.ExecuteNonQuery();

            Assert.True(File.Exists(databasePath));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    public static IEnumerable<object[]> PolicyIndexColumns()
    {
        var invalidValues = new[] { -1L, 4294967296L };
        foreach (var invalidValue in invalidValues)
        {
            yield return
            [
                SqliteDatabaseLayout.SecurityPolicies.TableName,
                SqliteDatabaseLayout.SecurityPolicies.PolicyIndexColumn,
                invalidValue
            ];
            yield return
            [
                SqliteDatabaseLayout.AtomicSecurityPolicies.TableName,
                SqliteDatabaseLayout.AtomicSecurityPolicies.OriginalIndexColumn,
                invalidValue
            ];
            yield return
            [
                SqliteDatabaseLayout.MergedSecurityPolicies.TableName,
                SqliteDatabaseLayout.MergedSecurityPolicies.MinimumIndexColumn,
                invalidValue
            ];
            yield return
            [
                SqliteDatabaseLayout.MergedSecurityPolicies.TableName,
                SqliteDatabaseLayout.MergedSecurityPolicies.MaximumIndexColumn,
                invalidValue
            ];
        }
    }

    [Theory]
    [MemberData(nameof(PolicyIndexColumns))]
    public void PolicyIndexColumns_RejectValuesOutsideUInt32Range(
        string tableName,
        string columnName,
        long invalidValue)
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            new SqliteImportedSecurityPolicyRepository(databaseDirectory).ReplaceAll([CreateImportedPolicy()]);
            new SqliteAtomicPolicyRepository(databaseDirectory).ReplaceAll([CreateAtomicPolicy(10, "atomic-policy")]);
            new SqliteMergedSecurityPolicyRepository(databaseDirectory).ReplaceAll([CreateMergedPolicy()]);

            Assert.Throws<SqliteException>(() => UpdateIndexColumn(databaseDirectory, tableName, columnName, invalidValue));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void ImportedSecurityPolicies_RejectDuplicatePolicyIndex()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var repository = new SqliteImportedSecurityPolicyRepository(databaseDirectory);

            Assert.Throws<SqliteException>(() => repository.ReplaceAll(
            [
                CreateImportedPolicy(index: 1, name: "allow-web-a"),
                CreateImportedPolicy(index: 1, name: "allow-web-b")
            ]));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void ImportedSecurityPolicies_RejectDuplicatePolicyName()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var repository = new SqliteImportedSecurityPolicyRepository(databaseDirectory);

            Assert.Throws<SqliteException>(() => repository.ReplaceAll(
            [
                CreateImportedPolicy(index: 1, name: "allow-web"),
                CreateImportedPolicy(index: 2, name: "allow-web")
            ]));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    private static ImportedSecurityPolicy CreateImportedPolicy(uint index = 1, string name = "allow-web")
    {
        return new ImportedSecurityPolicy
        {
            Index = index,
            Name = name,
            FromZones = ["trust"],
            SourceAddressReferences = ["src-group"],
            ToZones = ["untrust"],
            DestinationAddressReferences = ["dst-host"],
            Applications = ["web-browsing"],
            ServiceReferences = ["svc-https"],
            Action = SecurityPolicyAction.Allow,
            GroupId = "group-a"
        };
    }

    private static AtomicSecurityPolicy CreateAtomicPolicy(uint originalIndex, string originalPolicyName)
    {
        return new AtomicSecurityPolicy
        {
            FromZone = "trust",
            SourceAddress = new AddressValue { Start = 1, Finish = 1 },
            ToZone = "untrust",
            DestinationAddress = new AddressValue { Start = 2, Finish = 2 },
            Application = "any",
            Service = new ServiceValue
            {
                ProtocolStart = 6,
                ProtocolFinish = 6,
                SourcePortStart = 0,
                SourcePortFinish = 65535,
                DestinationPortStart = 80,
                DestinationPortFinish = 80,
                Kind = "service"
            },
            Action = SecurityPolicyAction.Allow,
            GroupId = "group-a",
            OriginalIndex = originalIndex,
            OriginalPolicyName = originalPolicyName
        };
    }

    private static MergedSecurityPolicy CreateMergedPolicy()
    {
        return new MergedSecurityPolicy
        {
            FromZones = ["trust"],
            SourceAddresses = [new AddressValue { Start = 1, Finish = 1 }],
            ToZones = ["untrust"],
            DestinationAddresses = [new AddressValue { Start = 2, Finish = 2 }],
            Applications = ["any"],
            Services =
            [
                new ServiceValue
                {
                    ProtocolStart = 6,
                    ProtocolFinish = 6,
                    SourcePortStart = 0,
                    SourcePortFinish = 65535,
                    DestinationPortStart = 80,
                    DestinationPortFinish = 80,
                    Kind = "service"
                }
            ],
            Action = SecurityPolicyAction.Allow,
            GroupId = "group-a",
            MinimumIndex = 10,
            MaximumIndex = 10,
            OriginalPolicyNames = ["merged-policy"]
        };
    }

    private static void UpdateIndexColumn(
        string databaseDirectory,
        string tableName,
        string columnName,
        long value)
    {
        var databasePath = Path.Combine(databaseDirectory, SqliteDatabaseLayout.DatabaseFileName);

        using var connection = SqliteRepositoryHelper.OpenConnection(databasePath);
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE " + tableName + " SET " + columnName + " = $value;";
        command.Parameters.AddWithValue("$value", value);
        command.ExecuteNonQuery();
    }

    private static void CreateAddressObjectDatabaseInRollbackJournalMode(string databaseDirectory)
    {
        Directory.CreateDirectory(databaseDirectory);
        var databasePath = Path.Combine(databaseDirectory, SqliteDatabaseLayout.DatabaseFileName);

        using var connection = new SqliteConnection($"Data Source={databasePath}");
        connection.Open();

        using (var journalModeCommand = connection.CreateCommand())
        {
            journalModeCommand.CommandText = "PRAGMA journal_mode=DELETE;";
            journalModeCommand.ExecuteNonQuery();
        }

        using (var createCommand = connection.CreateCommand())
        {
            createCommand.CommandText =
                "CREATE TABLE " + SqliteDatabaseLayout.AddressObjects.TableName + " (" +
                SqliteDatabaseLayout.AddressObjects.NameColumn + " TEXT NOT NULL PRIMARY KEY, " +
                SqliteDatabaseLayout.AddressObjects.ValueColumn + " TEXT NOT NULL);";
            createCommand.ExecuteNonQuery();
        }

        using var insertCommand = connection.CreateCommand();
        insertCommand.CommandText =
            "INSERT INTO " + SqliteDatabaseLayout.AddressObjects.TableName +
            "(" + SqliteDatabaseLayout.AddressObjects.NameColumn + ", " + SqliteDatabaseLayout.AddressObjects.ValueColumn + ") " +
            "VALUES ($name, $value);";
        insertCommand.Parameters.AddWithValue("$name", "host-a");
        insertCommand.Parameters.AddWithValue("$value", "192.168.1.10/32");
        insertCommand.ExecuteNonQuery();
    }

    private static string ReadJournalMode(string databaseDirectory)
    {
        var databasePath = Path.Combine(databaseDirectory, SqliteDatabaseLayout.DatabaseFileName);

        using var connection = new SqliteConnection($"Data Source={databasePath}");
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode;";

        return command.ExecuteScalar()?.ToString() ?? string.Empty;
    }

    private static string CreateTempDatabaseDirectory()
    {
        return Path.Combine(Path.GetTempPath(), $"fwrule-tool-test-{Guid.NewGuid():N}");
    }

    private static void DeleteDatabaseDirectory(string databaseDirectory)
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(databaseDirectory))
        {
            Directory.Delete(databaseDirectory, recursive: true);
        }
    }
}
