using FirewallRuleToolkit.App;
using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Config;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Exceptions;
using FirewallRuleToolkit.Domain.Ports;

namespace FirewallRuleToolkit.Tests.App;

public sealed class ExportUseCaseTests
{
    [Fact]
    public void Execute_WhenAtomicAndMergedAreSelected_ExportsBothRepositories()
    {
        var atomicSource = new StubReadRepository<AtomicSecurityPolicy>([]);
        var atomicDestination = new StubWriteRepository<AtomicSecurityPolicy>();
        var mergedSource = new StubReadRepository<MergedSecurityPolicy>([]);
        var mergedDestination = new StubWriteRepository<MergedSecurityPolicy>();

        var exitCode = ExportUseCase.Execute(
            ExportTarget.Atomic | ExportTarget.Merged,
            atomicSource,
            atomicDestination,
            mergedSource,
            mergedDestination);

        Assert.Equal(0, exitCode);
        Assert.True(atomicSource.EnsureAvailableCalled);
        Assert.True(atomicDestination.ReplaceAllCalled);
        Assert.True(mergedSource.EnsureAvailableCalled);
        Assert.True(mergedDestination.ReplaceAllCalled);
    }

    [Fact]
    public void Execute_WhenRequiredRepositoryIsMissing_ThrowsInvalidOperationException()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ExportUseCase.Execute(
            ExportTarget.Atomic,
            null,
            new StubWriteRepository<AtomicSecurityPolicy>(),
            null,
            null));

        Assert.Contains("atomicSource", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Execute_WhenSourceIsUnavailable_ThrowsApplicationUsageException()
    {
        var source = new StubReadRepository<AtomicSecurityPolicy>([], isAvailable: false);

        var exception = Assert.Throws<ApplicationUsageException>(() => ExportUseCase.Execute(
            ExportTarget.Atomic,
            source,
            new StubWriteRepository<AtomicSecurityPolicy>(),
            null,
            null));

        Assert.Contains("Atomize has not been executed", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Execute_WhenMergedSourceIsUnavailable_DoesNotExportAtomic()
    {
        var atomicSource = new StubReadRepository<AtomicSecurityPolicy>([]);
        var atomicDestination = new StubWriteRepository<AtomicSecurityPolicy>();
        var mergedSource = new StubReadRepository<MergedSecurityPolicy>([], isAvailable: false);
        var mergedDestination = new StubWriteRepository<MergedSecurityPolicy>();

        var exception = Assert.Throws<ApplicationUsageException>(() => ExportUseCase.Execute(
            ExportTarget.Atomic | ExportTarget.Merged,
            atomicSource,
            atomicDestination,
            mergedSource,
            mergedDestination));

        Assert.Contains("Merge has not been executed", exception.Message, StringComparison.Ordinal);
        Assert.True(atomicSource.EnsureAvailableCalled);
        Assert.True(mergedSource.EnsureAvailableCalled);
        Assert.False(atomicDestination.ReplaceAllCalled);
        Assert.False(mergedDestination.ReplaceAllCalled);
    }

    private sealed class StubReadRepository<T>(IReadOnlyList<T> items, bool isAvailable = true) : IReadRepository<T>
    {
        private readonly IReadOnlyList<T> items = items;
        private readonly bool isAvailable = isAvailable;

        public bool EnsureAvailableCalled { get; private set; }

        public void EnsureAvailable()
        {
            EnsureAvailableCalled = true;
            if (!isAvailable)
            {
                throw new RepositoryUnavailableException("unavailable");
            }
        }

        public IEnumerable<T> GetAll()
        {
            return items;
        }
    }

    private sealed class StubWriteRepository<T> : IWriteRepository<T>
    {
        public bool ReplaceAllCalled { get; private set; }

        public void Initialize()
        {
        }

        public void Complete()
        {
        }

        public void AppendRange(IEnumerable<T> items)
        {
        }

        public void ReplaceAll(IEnumerable<T> items)
        {
            ReplaceAllCalled = true;
            _ = items.ToArray();
        }
    }
}
