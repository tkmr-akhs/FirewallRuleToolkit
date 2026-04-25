using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Exceptions;
using FirewallRuleToolkit.Domain.Ports;

namespace FirewallRuleToolkit.Tests.App;

internal sealed class TestReadRepository<T>(
    IEnumerable<T> items,
    bool isAvailable = true) : IReadRepository<T>
{
    private readonly IReadOnlyList<T> items = items.ToArray();
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

internal sealed class TestAtomicPolicyMergeSource(
    IEnumerable<AtomicSecurityPolicy> items,
    bool isAvailable = true) : IAtomicPolicyMergeSource
{
    private readonly IReadOnlyList<AtomicSecurityPolicy> items = items.ToArray();
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

    public IEnumerable<AtomicSecurityPolicy> GetAll()
    {
        return items;
    }

    public IEnumerable<AtomicSecurityPolicy> GetAllOrderedForMerge()
    {
        return items;
    }
}

internal sealed class TestItemCountRepository(int count, bool isAvailable = true) : IItemCountRepository
{
    private readonly int count = count;
    private readonly bool isAvailable = isAvailable;

    public void EnsureAvailable()
    {
        if (!isAvailable)
        {
            throw new RepositoryUnavailableException("unavailable");
        }
    }

    public int Count()
    {
        return count;
    }
}

internal sealed class TestWriteRepositorySession : IWriteRepositorySession
{
    public TestAddressObjectRepository AddressObjectsRepository { get; } = new();

    public TestAddressGroupRepository AddressGroupsRepository { get; } = new();

    public TestServiceObjectRepository ServiceObjectsRepository { get; } = new();

    public TestServiceGroupRepository ServiceGroupsRepository { get; } = new();

    public TestReadWriteRepository<ImportedSecurityPolicy> ImportedSecurityPoliciesRepository { get; } = new();

    public TestReadWriteRepository<AtomicSecurityPolicy> AtomicPoliciesRepository { get; } = new();

    public TestReadWriteRepository<MergedSecurityPolicy> MergedSecurityPoliciesRepository { get; } = new();

    public TestToolMetadataRepository ToolMetadataRepository { get; } = new();

    public int CommitCount { get; private set; }

    public IReadWriteRepository<AddressObject> AddressObjects => AddressObjectsRepository;

    public IReadWriteRepository<AddressGroupMembership> AddressGroups => AddressGroupsRepository;

    public IReadWriteRepository<ServiceObject> ServiceObjects => ServiceObjectsRepository;

    public IReadWriteRepository<ServiceGroupMembership> ServiceGroups => ServiceGroupsRepository;

    public IWriteRepository<ImportedSecurityPolicy> ImportedSecurityPolicies => ImportedSecurityPoliciesRepository;

    public IReadWriteRepository<AtomicSecurityPolicy> AtomicPolicies => AtomicPoliciesRepository;

    public IReadWriteRepository<MergedSecurityPolicy> MergedSecurityPolicies => MergedSecurityPoliciesRepository;

    public IToolMetadataRepository ToolMetadata => ToolMetadataRepository;

    public void Commit()
    {
        CommitCount++;
    }

    public void Dispose()
    {
    }
}

internal class TestReadWriteRepository<T> : IReadWriteRepository<T>
{
    public List<T> Items { get; } = [];

    public List<int> AppendBatchSizes { get; } = [];

    public int CompleteCount { get; private set; }

    public Exception? AppendException { get; set; }

    public void EnsureAvailable()
    {
    }

    public IEnumerable<T> GetAll()
    {
        return Items;
    }

    public void Initialize()
    {
        Items.Clear();
        AppendBatchSizes.Clear();
    }

    public void Complete()
    {
        CompleteCount++;
    }

    public void AppendRange(IEnumerable<T> items)
    {
        if (AppendException is not null)
        {
            throw AppendException;
        }

        var batch = items.ToArray();
        AppendBatchSizes.Add(batch.Length);
        Items.AddRange(batch);
    }

    public void ReplaceAll(IEnumerable<T> items)
    {
        Initialize();
        AppendRange(items);
    }
}

internal sealed class TestAddressObjectRepository : TestReadWriteRepository<AddressObject>
{
}

internal sealed class TestAddressGroupRepository : TestReadWriteRepository<AddressGroupMembership>
{
}

internal sealed class TestServiceObjectRepository : TestReadWriteRepository<ServiceObject>
{
}

internal sealed class TestServiceGroupRepository : TestReadWriteRepository<ServiceGroupMembership>
{
}

internal sealed class TestToolMetadataRepository : IToolMetadataRepository
{
    public int ClearCount { get; private set; }

    public int SetAtomizeThresholdCount { get; private set; }

    public int? AtomizeThreshold { get; private set; }

    public void EnsureAvailable()
    {
    }

    public void SetAtomizeThreshold(int threshold)
    {
        SetAtomizeThresholdCount++;
        AtomizeThreshold = threshold;
    }

    public bool TryGetAtomizeThreshold(out int threshold)
    {
        if (AtomizeThreshold.HasValue)
        {
            threshold = AtomizeThreshold.Value;
            return true;
        }

        threshold = default;
        return false;
    }

    public void Clear()
    {
        ClearCount++;
        AtomizeThreshold = null;
    }
}
