using FirewallRuleToolkit.Domain.Exceptions;
using FirewallRuleToolkit.Infra.Sqlite;
using Microsoft.Data.Sqlite;

namespace FirewallRuleToolkit.Tests.Infra.Sqlite;

public sealed class SqliteToolMetadataRepositoryTests
{
    [Fact]
    public void SetAtomizeThreshold_ThenTryGetAtomizeThreshold_ReturnsSavedValue()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var repository = new SqliteToolMetadataRepository(databaseDirectory);
            repository.SetAtomizeThreshold(12);

            Assert.True(repository.TryGetAtomizeThreshold(out var threshold));
            Assert.Equal(12, threshold);
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void Clear_RemovesSavedThreshold()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();

        try
        {
            var repository = new SqliteToolMetadataRepository(databaseDirectory);
            repository.SetAtomizeThreshold(12);
            repository.Clear();

            Assert.False(repository.TryGetAtomizeThreshold(out _));
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
    }

    [Fact]
    public void EnsureAvailable_WhenTableDoesNotExist_ThrowsRepositoryUnavailableException()
    {
        var databaseDirectory = CreateTempDatabaseDirectory();
        Directory.CreateDirectory(databaseDirectory);
        var databasePath = Path.Combine(databaseDirectory, SqliteDatabaseLayout.DatabaseFileName);

        try
        {
            using (var connection = new SqliteConnection($"Data Source={databasePath}"))
            {
                connection.Open();
            }

            var repository = new SqliteToolMetadataRepository(databaseDirectory);
            Assert.Throws<RepositoryUnavailableException>(repository.EnsureAvailable);
        }
        finally
        {
            DeleteDatabaseDirectory(databaseDirectory);
        }
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
