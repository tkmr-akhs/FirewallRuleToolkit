using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.Exceptions;
using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.ValueObjects;
using FirewallRuleToolkit.Infra.Sqlite;
using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Tests.Infra.Sqlite;

public sealed class SqliteAtomicPolicyRepositoryTests
{
    [Fact]
    public void Commit_PublishesNewSnapshot()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            IWriteRepositorySessionFactory sessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);

            using (var writeSession = sessionFactory.BeginWriteSession())
            {
                writeSession.AtomicPolicies.Initialize();
                writeSession.AtomicPolicies.AppendRange([CreateAtomicPolicy(10, "published")]);
                writeSession.Commit();
            }

            Assert.Equal(
                ["published"],
                new SqliteAtomicPolicyRepository(databaseDirectory).GetAll().Select(static policy => policy.OriginalPolicyName));
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
            var publishedRepository = new SqliteAtomicPolicyRepository(databaseDirectory);
            publishedRepository.ReplaceAll([CreateAtomicPolicy(10, "published")]);

            IWriteRepositorySessionFactory sessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);

            using (var writeSession = sessionFactory.BeginWriteSession())
            {
                writeSession.AtomicPolicies.Initialize();
                writeSession.AtomicPolicies.AppendRange([CreateAtomicPolicy(20, "pending")]);
            }

            Assert.Equal(["published"], publishedRepository.GetAll().Select(static policy => policy.OriginalPolicyName));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void DisposeWithoutCommit_RollsBackNewSnapshot()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            IWriteRepositorySessionFactory sessionFactory = new SqliteRepositorySessionFactory(databaseDirectory);

            using (var writeSession = sessionFactory.BeginWriteSession())
            {
                writeSession.AtomicPolicies.Initialize();
                writeSession.AtomicPolicies.AppendRange([CreateAtomicPolicy(10, "pending")]);
            }

            Assert.Throws<RepositoryUnavailableException>(new SqliteAtomicPolicyRepository(databaseDirectory).EnsureAvailable);
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void Count_ReturnsStoredRowCount()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var repository = new SqliteAtomicPolicyRepository(databaseDirectory);
            repository.ReplaceAll(
            [
                CreateAtomicPolicy(10, "first"),
                CreateAtomicPolicy(20, "second")
            ]);

            IItemCountRepository counter = repository;

            Assert.Equal(2, counter.Count());
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void GetAllOrderedForMerge_OrdersByMergePartitionOriginalIndexAndStorageOrder()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var repository = new SqliteAtomicPolicyRepository(databaseDirectory);
            repository.ReplaceAll(
            [
                CreateAtomicPolicy(30, "trust-b-untrust-kind-b", fromZone: "trust-b", serviceKind: "kind-b"),
                CreateAtomicPolicy(20, "trust-untrust-kind-b", serviceKind: "kind-b"),
                CreateAtomicPolicy(30, "trust-untrust-kind-a-late", serviceKind: "kind-a"),
                CreateAtomicPolicy(10, "trust-untrust-kind-a-first", serviceKind: "kind-a"),
                CreateAtomicPolicy(10, "trust-untrust-kind-a-second", serviceKind: "kind-a"),
                CreateAtomicPolicy(5, "dmz-untrust-kind-a", fromZone: "dmz", serviceKind: "kind-a"),
                CreateAtomicPolicy(1, "trust-dmz-kind-a", toZone: "dmz", serviceKind: "kind-a")
            ]);

            var orderedNames = repository
                .GetAllOrderedForMerge()
                .Select(static policy => policy.OriginalPolicyName)
                .ToArray();

            Assert.Equal(
            [
                "dmz-untrust-kind-a",
                "trust-dmz-kind-a",
                "trust-untrust-kind-a-first",
                "trust-untrust-kind-a-second",
                "trust-untrust-kind-a-late",
                "trust-untrust-kind-b",
                "trust-b-untrust-kind-b"
            ],
            orderedNames);
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    private static AtomicSecurityPolicy CreateAtomicPolicy(
        uint originalIndex,
        string originalPolicyName,
        string fromZone = "trust",
        string toZone = "untrust",
        string? serviceKind = "service")
    {
        return new AtomicSecurityPolicy
        {
            FromZone = fromZone,
            SourceAddress = new AddressValue { Start = 1, Finish = 1 },
            ToZone = toZone,
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
                Kind = serviceKind
            },
            Action = SecurityPolicyAction.Allow,
            GroupId = "group-a",
            OriginalIndex = originalIndex,
            OriginalPolicyName = originalPolicyName
        };
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
