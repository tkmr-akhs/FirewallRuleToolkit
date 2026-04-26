using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.Ports;
using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.App;

[Collection("ProgramLogger")]
public sealed class AtomizeUseCaseTests
{
    [Fact]
    public void Execute_WhenProcessedCountReachesInterval_ReportsProgressEvery200Policies()
    {
        var reportedCounts = new List<int>();
        var source = new TestReadRepository<ImportedSecurityPolicy>(
            Enumerable.Range(1, 450).Select(static index => CreatePolicy(index)));
        var writeSession = new TestWriteRepositorySession();

        var exitCode = AtomizeUseCase.Execute(
            threshold: 10,
            securityPolicyResolver: CreateResolver(),
            sourceSecurityPolicies: source,
            writeSession: writeSession,
            reportProgress: reportedCounts.Add);

        Assert.Equal(0, exitCode);
        Assert.Equal([200, 400], reportedCounts);
        Assert.Equal(10, writeSession.ToolMetadataRepository.AtomizeThreshold);
        Assert.Equal(1, writeSession.ToolMetadataRepository.SetAtomizeThresholdCount);
    }

    [Fact]
    public void Execute_WhenSkippedPolicyOccurs_StillReportsBasedOnSourcePolicyCount()
    {
        var reportedCounts = new List<int>();
        var source = new TestReadRepository<ImportedSecurityPolicy>(
            Enumerable.Range(1, 200).Select(static index =>
                index == 200
                    ? CreatePolicy(index, sourceAddressValue: "invalid")
                    : CreatePolicy(index)));
        var writeSession = new TestWriteRepositorySession();

        var exitCode = AtomizeUseCase.Execute(
            threshold: 10,
            securityPolicyResolver: CreateResolver(),
            sourceSecurityPolicies: source,
            writeSession: writeSession,
            reportProgress: reportedCounts.Add);

        Assert.Equal(0, exitCode);
        Assert.Equal([200], reportedCounts);
        Assert.Equal(10, writeSession.ToolMetadataRepository.AtomizeThreshold);
    }

    [Fact]
    public void Execute_WhenAppendFails_ThrowsAndDoesNotTreatItAsSkippedPolicy()
    {
        var source = new TestReadRepository<ImportedSecurityPolicy>([CreatePolicy(1)]);
        var writeSession = new TestWriteRepositorySession();
        writeSession.AtomicPoliciesRepository.AppendException = new FormatException("write failed");

        Assert.Throws<FormatException>(() =>
            AtomizeUseCase.Execute(
                threshold: 10,
                securityPolicyResolver: CreateResolver(),
                sourceSecurityPolicies: source,
                writeSession: writeSession));
    }

    [Fact]
    public void Execute_AtomizesPoliciesRegardlessOfAction()
    {
        var source = new TestReadRepository<ImportedSecurityPolicy>(
        [
            CreatePolicy(1, SecurityPolicyAction.Allow),
            CreatePolicy(2, SecurityPolicyAction.Deny),
            CreatePolicy(3, SecurityPolicyAction.Drop)
        ]);
        var writeSession = new TestWriteRepositorySession();

        var exitCode = AtomizeUseCase.Execute(
            threshold: 10,
            securityPolicyResolver: CreateResolver(),
            sourceSecurityPolicies: source,
            writeSession: writeSession);

        Assert.Equal(0, exitCode);
        Assert.Equal(
            [SecurityPolicyAction.Allow, SecurityPolicyAction.Deny, SecurityPolicyAction.Drop],
            writeSession.AtomicPoliciesRepository.Items.Select(static policy => policy.Action));
        Assert.Equal(10, writeSession.ToolMetadataRepository.AtomizeThreshold);
    }

    private static ImportedSecurityPolicy CreatePolicy(
        int index,
        SecurityPolicyAction action = SecurityPolicyAction.Allow,
        string sourceAddressValue = "10.0.0.1")
    {
        return new ImportedSecurityPolicy
        {
            Name = $"policy-{index}",
            Index = (uint)index,
            FromZones = ["trust"],
            SourceAddressReferences = [sourceAddressValue],
            ToZones = ["untrust"],
            DestinationAddressReferences = ["10.0.0.2"],
            Applications = ["any"],
            ServiceReferences = ["service-http"],
            Action = action,
            GroupId = $"group-{index}"
        };
    }

    private static SecurityPolicyResolver CreateResolver()
    {
        return new SecurityPolicyResolver(
            new AddressReferenceResolver(
                new EmptyAddressObjectLookup(),
                new EmptyAddressGroupLookup()),
            new ServiceReferenceResolver(
                new FixedServiceObjectLookup(),
                new EmptyServiceGroupLookup()));
    }

    private sealed class EmptyAddressObjectLookup : ILookupRepository<string>
    {
        public bool TryGetByName(string name, out string value)
        {
            value = string.Empty;
            return false;
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class EmptyAddressGroupLookup : ILookupRepository<IReadOnlyList<string>>
    {
        public bool TryGetByName(string groupName, out IReadOnlyList<string> members)
        {
            members = [];
            return false;
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class FixedServiceObjectLookup : ILookupRepository<ServiceObject>
    {
        public bool TryGetByName(string name, out ServiceObject serviceObject)
        {
            if (name.Equals("service-http", StringComparison.Ordinal))
            {
                serviceObject = new ServiceObject
                {
                    Name = "service-http",
                    Protocol = "6",
                    SourcePort = "0-65535",
                    DestinationPort = "80",
                    Kind = "service"
                };
                return true;
            }

            serviceObject = null!;
            return false;
        }

        public void EnsureAvailable()
        {
        }
    }

    private sealed class EmptyServiceGroupLookup : ILookupRepository<IReadOnlyList<string>>
    {
        public bool TryGetByName(string groupName, out IReadOnlyList<string> members)
        {
            members = [];
            return false;
        }

        public void EnsureAvailable()
        {
        }
    }
}
