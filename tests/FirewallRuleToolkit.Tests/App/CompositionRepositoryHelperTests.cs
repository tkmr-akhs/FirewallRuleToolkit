using FirewallRuleToolkit.App.Composition;
using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.Exceptions;

namespace FirewallRuleToolkit.Tests.App;

public sealed class CompositionRepositoryHelperTests
{
    [Fact]
    public void EnsureAvailableOrThrow_WhenRepositoryIsUnavailable_ThrowsMappedException()
    {
        var repository = new StubReadRepository<int>([], available: false);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            CompositionRepositoryHelper.EnsureAvailableOrThrow(
                repository.EnsureAvailable,
                static ex => new InvalidOperationException("mapped", ex)));

        Assert.Equal("mapped", exception.Message);
        Assert.IsType<RepositoryUnavailableException>(exception.InnerException);
    }

    [Fact]
    public void TryEnsureAvailable_WhenAnyRepositoryIsUnavailable_ReturnsFalse()
    {
        var availableRepository = new StubReadRepository<int>([1], available: true);
        var unavailableRepository = new StubReadRepository<int>([], available: false);

        var result = CompositionRepositoryHelper.TryEnsureAvailable(
            availableRepository.EnsureAvailable,
            unavailableRepository.EnsureAvailable);

        Assert.False(result);
    }

    [Fact]
    public void CountAvailableItems_WhenCountRepositoryIsAvailable_UsesRepositoryCount()
    {
        var repository = new StubCountRepository(count: 4, available: true);

        var count = CompositionRepositoryHelper.CountAvailableItems(repository);

        Assert.Equal(4, count);
        Assert.Equal(1, repository.CountCallCount);
    }

    [Fact]
    public void ExecuteWhenAvailable_WhenAllRepositoriesAreAvailable_ReturnsActionResult()
    {
        var left = new StubReadRepository<int>([1, 2], available: true);
        var right = new StubReadRepository<int>([3], available: true);

        var count = CompositionRepositoryHelper.ExecuteWhenAvailable(
            () => CompositionRepositoryHelper.CountItems(left.GetAll()) + CompositionRepositoryHelper.CountItems(right.GetAll()),
            static ex => new InvalidOperationException("mapped", ex),
            left.EnsureAvailable,
            right.EnsureAvailable);

        Assert.Equal(3, count);
    }

    [Fact]
    public void ExecuteReadOrThrow_WhenRepositoryReadFails_ThrowsMappedException()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            CompositionRepositoryHelper.ExecuteReadOrThrow<int>(
                static () => throw new RepositoryReadException("read failed"),
                static ex => new InvalidOperationException("mapped", ex)));

        Assert.Equal("mapped", exception.Message);
        Assert.IsType<RepositoryReadException>(exception.InnerException);
    }

    private sealed class StubReadRepository<T> : IReadRepository<T>
    {
        private readonly IReadOnlyList<T> items;
        private readonly bool available;

        public StubReadRepository(IReadOnlyList<T> items, bool available)
        {
            this.items = items;
            this.available = available;
        }

        public void EnsureAvailable()
        {
            if (!available)
            {
                throw new RepositoryUnavailableException("unavailable");
            }
        }

        public IEnumerable<T> GetAll()
        {
            return items;
        }
    }

    private sealed class StubCountRepository : IItemCountRepository
    {
        private readonly int count;
        private readonly bool available;

        public StubCountRepository(int count, bool available)
        {
            this.count = count;
            this.available = available;
        }

        public int CountCallCount { get; private set; }

        public void EnsureAvailable()
        {
            if (!available)
            {
                throw new RepositoryUnavailableException("unavailable");
            }
        }

        public int Count()
        {
            CountCallCount++;
            return count;
        }
    }
}
