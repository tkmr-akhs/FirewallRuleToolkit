using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;
using FirewallRuleToolkit.Infra.Sqlite;
using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Tests.Infra.Sqlite;

public sealed class SqliteMergedSecurityPolicyRepositoryTests
{
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
