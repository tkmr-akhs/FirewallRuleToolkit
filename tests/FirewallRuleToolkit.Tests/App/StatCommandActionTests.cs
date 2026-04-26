using FirewallRuleToolkit.App.UseCases;

namespace FirewallRuleToolkit.Tests.App;

public sealed class StatUseCaseTests
{
    [Fact]
    public void Execute_WhenAllAvailable_WritesAllCounts()
    {
        var lines = new List<string>();

        var exitCode = ExecuteStat(
            securityPolicyCount: 10,
            addressDefinitionCount: 20,
            addressGroupCount: 30,
            serviceDefinitionCount: 40,
            serviceGroupCount: 50,
            atomicPolicyCount: 60,
            mergedPolicyCount: 70,
            lines);

        Assert.Equal(0, exitCode);
        Assert.Equal(
        [
            string.Empty,
            "Import: completed",
            "security_policies: 10",
            "address_objects: 20",
            "address_group_members: 30",
            "service_objects: 40",
            "service_group_members: 50",
            string.Empty,
            "Atomize: completed",
            "atomic_security_policies: 60",
            string.Empty,
            "Merge: completed",
            "merged_security_policies: 70",
            string.Empty
        ],
        lines);
    }

    [Fact]
    public void Execute_WhenUnavailable_WritesNotProcessedStatus()
    {
        var lines = new List<string>();

        var exitCode = StatUseCase.Execute(
            new TestItemCountRepository(0, isAvailable: false),
            new TestItemCountRepository(0),
            new TestItemCountRepository(0),
            new TestItemCountRepository(0),
            new TestItemCountRepository(0),
            new TestItemCountRepository(0, isAvailable: false),
            new TestItemCountRepository(0, isAvailable: false),
            lines.Add);

        Assert.Equal(0, exitCode);
        Assert.Equal(
        [
            string.Empty,
            "Import: not imported",
            "Atomize: not atomized",
            "Merge: not merged",
            string.Empty
        ],
        lines);
    }

    [Fact]
    public void Execute_WhenImportDoneAndAtomizeNotDone_AddsBlankLineOnlyAfterImport()
    {
        var lines = new List<string>();

        var exitCode = StatUseCase.Execute(
            new TestItemCountRepository(1),
            new TestItemCountRepository(2),
            new TestItemCountRepository(3),
            new TestItemCountRepository(4),
            new TestItemCountRepository(5),
            new TestItemCountRepository(0, isAvailable: false),
            new TestItemCountRepository(6),
            lines.Add);

        Assert.Equal(0, exitCode);
        Assert.Equal(
        [
            string.Empty,
            "Import: completed",
            "security_policies: 1",
            "address_objects: 2",
            "address_group_members: 3",
            "service_objects: 4",
            "service_group_members: 5",
            string.Empty,
            "Atomize: not atomized",
            "Merge: completed",
            "merged_security_policies: 6",
            string.Empty
        ],
        lines);
    }

    private static int ExecuteStat(
        int securityPolicyCount,
        int addressDefinitionCount,
        int addressGroupCount,
        int serviceDefinitionCount,
        int serviceGroupCount,
        int atomicPolicyCount,
        int mergedPolicyCount,
        List<string> lines)
    {
        return StatUseCase.Execute(
            new TestItemCountRepository(securityPolicyCount),
            new TestItemCountRepository(addressDefinitionCount),
            new TestItemCountRepository(addressGroupCount),
            new TestItemCountRepository(serviceDefinitionCount),
            new TestItemCountRepository(serviceGroupCount),
            new TestItemCountRepository(atomicPolicyCount),
            new TestItemCountRepository(mergedPolicyCount),
            lines.Add);
    }
}
