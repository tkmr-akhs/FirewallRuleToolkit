using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;
using FirewallRuleToolkit.Infra.Sqlite;
using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Tests.Infra.Sqlite;

public sealed class SqliteMergedSecurityPolicyRepositoryTests
{
    [Fact]
    public void ReplaceAll_StoresConditionCollectionsInCanonicalJsonOrder()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var repository = new SqliteMergedSecurityPolicyRepository(databaseDirectory);
            repository.ReplaceAll(
            [
                new MergedSecurityPolicy
                {
                    FromZones = ["z"],
                    SourceAddresses =
                    [
                        new AddressValue { Start = 10, Finish = 10 },
                        new AddressValue { Start = 1, Finish = 2 }
                    ],
                    ToZones = ["z"],
                    DestinationAddresses =
                    [
                        new AddressValue { Start = 20, Finish = 20 },
                        new AddressValue { Start = 3, Finish = 4 }
                    ],
                    Applications = ["z-app", "a-app"],
                    Services =
                    [
                        CreateTcpService(80),
                        CreateKindService(),
                        CreateAnyService()
                    ],
                    Action = SecurityPolicyAction.Allow,
                    GroupId = "group-a",
                    MinimumIndex = 1,
                    MaximumIndex = 1,
                    OriginalPolicyNames = ["p"]
                }
            ]);

            using var connection = new SqliteConnection(
                $"Data Source={Path.Combine(databaseDirectory, SqliteDatabaseLayout.DatabaseFileName)}");
            connection.Open();

            using var command = connection.CreateCommand();
            command.CommandText =
                "SELECT source_addresses_json, destination_addresses_json, application_json, services_json " +
                "FROM merged_security_policies;";

            using var reader = command.ExecuteReader();
            Assert.True(reader.Read());
            Assert.Equal("[{\"s\":1,\"f\":2},{\"s\":10,\"f\":10}]", reader.GetString(0));
            Assert.Equal("[{\"s\":3,\"f\":4},{\"s\":20,\"f\":20}]", reader.GetString(1));
            Assert.Equal("[\"a-app\",\"z-app\"]", reader.GetString(2));
            Assert.Equal(
                "[{\"ps\":0,\"pf\":255,\"ss\":0,\"sf\":65535,\"ds\":0,\"df\":65535,\"k\":null},{\"ps\":255,\"pf\":255,\"ss\":0,\"sf\":0,\"ds\":0,\"df\":0,\"k\":\"application-default\"},{\"ps\":6,\"pf\":6,\"ss\":0,\"sf\":65535,\"ds\":80,\"df\":80,\"k\":null}]",
                reader.GetString(3));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void GetAll_OrdersByMinimumIndexMaximumIndexAndStorageOrder()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var repository = new SqliteMergedSecurityPolicyRepository(databaseDirectory);
            repository.ReplaceAll(
            [
                CreateMergedPolicy(10, 30, "minimum-10-maximum-30"),
                CreateMergedPolicy(10, 20, "minimum-10-maximum-20-first"),
                CreateMergedPolicy(5, 50, "minimum-5-maximum-50"),
                CreateMergedPolicy(10, 20, "minimum-10-maximum-20-second")
            ]);

            var orderedNames = repository
                .GetAll()
                .Select(static policy => policy.OriginalPolicyNames.Single())
                .ToArray();

            Assert.Equal(
            [
                "minimum-5-maximum-50",
                "minimum-10-maximum-20-first",
                "minimum-10-maximum-20-second",
                "minimum-10-maximum-30"
            ],
            orderedNames);
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    private static ServiceValue CreateAnyService()
    {
        return new ServiceValue
        {
            ProtocolStart = 0,
            ProtocolFinish = 255,
            SourcePortStart = 0,
            SourcePortFinish = 65535,
            DestinationPortStart = 0,
            DestinationPortFinish = 65535,
            Kind = null
        };
    }

    private static ServiceValue CreateKindService()
    {
        return new ServiceValue
        {
            ProtocolStart = 255,
            ProtocolFinish = 255,
            SourcePortStart = 0,
            SourcePortFinish = 0,
            DestinationPortStart = 0,
            DestinationPortFinish = 0,
            Kind = "application-default"
        };
    }

    private static ServiceValue CreateTcpService(uint destinationPort)
    {
        return new ServiceValue
        {
            ProtocolStart = 6,
            ProtocolFinish = 6,
            SourcePortStart = 0,
            SourcePortFinish = 65535,
            DestinationPortStart = destinationPort,
            DestinationPortFinish = destinationPort,
            Kind = null
        };
    }

    private static MergedSecurityPolicy CreateMergedPolicy(
        uint minimumIndex,
        uint maximumIndex,
        string originalPolicyName)
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
            MinimumIndex = minimumIndex,
            MaximumIndex = maximumIndex,
            OriginalPolicyNames = [originalPolicyName]
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
