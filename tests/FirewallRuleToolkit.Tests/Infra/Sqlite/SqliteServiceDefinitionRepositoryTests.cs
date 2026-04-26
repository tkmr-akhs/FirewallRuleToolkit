using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Infra.Sqlite;
using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Tests.Infra.Sqlite;

public sealed class SqliteServiceDefinitionRepositoryTests
{
    [Fact]
    public void ReplaceAll_CreatesServiceDefinitionsTableWithKindColumn()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();
        var databasePath = Path.Combine(databaseDirectory, SqliteDatabaseLayout.DatabaseFileName);

        try
        {
            var store = new SqliteServiceDefinitionRepository(databaseDirectory);
            store.ReplaceAll(
            [
                new ServiceDefinition
                {
                    Name = "svc-web",
                    Protocol = "6",
                    SourcePort = "1-65535",
                    DestinationPort = "443",
                    Kind = "application-default"
                }
            ]);

            using var connection = new SqliteConnection($"Data Source={databasePath}");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA table_info(service_objects);";

            using var reader = command.ExecuteReader();
            var columns = new List<string>();
            while (reader.Read())
            {
                columns.Add(reader.GetString(1));
            }

            Assert.Equal(["name", "protocol", "source_port", "destination_port", "kind"], columns);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(databaseDirectory))
            {
                Directory.Delete(databaseDirectory, recursive: true);
            }
        }
    }

    [Fact]
    public void GetAll_ReturnsStoredKind()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var store = new SqliteServiceDefinitionRepository(databaseDirectory);
            store.ReplaceAll(
            [
                new ServiceDefinition
                {
                    Name = "svc-web",
                    Protocol = "6",
                    SourcePort = "1-65535",
                    DestinationPort = "443",
                    Kind = "application-default"
                }
            ]);

            var serviceDefinition = Assert.Single(store.GetAll());

            Assert.NotNull(serviceDefinition);
            Assert.Equal("svc-web", serviceDefinition.Name);
            Assert.Equal("6", serviceDefinition.Protocol);
            Assert.Equal("1-65535", serviceDefinition.SourcePort);
            Assert.Equal("443", serviceDefinition.DestinationPort);
            Assert.Equal("application-default", serviceDefinition.Kind);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(databaseDirectory))
            {
                Directory.Delete(databaseDirectory, recursive: true);
            }
        }
    }

    private static string CreateTempDatabaseDirectory()
    {
        return Path.Combine(Path.GetTempPath(), $"fwrule-tool-test-{Guid.NewGuid():N}");
    }
}
