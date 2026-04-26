using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;

namespace FirewallRuleToolkit.Tests.App;

public sealed class ImportUseCaseTests
{
    [Fact]
    public void Execute_ImportsInBatches_AndKeepsPolicyReferencesUnresolved()
    {
        var addressDefinitionReader = new TestReadRepository<AddressDefinition>(
        [
            new AddressDefinition { Name = "src-host", Value = "192.168.0.10/32" },
            new AddressDefinition { Name = "dst-host", Value = "10.0.0.10/32" }
        ]);
        var addressGroupReader = new TestReadRepository<AddressGroupMembership>(
        [
            new AddressGroupMembership { GroupName = "src-group", MemberName = "src-host" }
        ]);
        var serviceDefinitionReader = new TestReadRepository<ServiceDefinition>(
        [
            new ServiceDefinition
            {
                Name = "svc-https",
                Protocol = "6",
                SourcePort = "1-65535",
                DestinationPort = "443",
                Kind = null
            }
        ]);
        var serviceGroupReader = new TestReadRepository<ServiceGroupMembership>(
        [
            new ServiceGroupMembership { GroupName = "svc-group", MemberName = "svc-https" }
        ]);
        var securityPolicyReader = new TestReadRepository<ImportedSecurityPolicy>(
        [
            new ImportedSecurityPolicy
            {
                Index = 1,
                Name = "allow-web",
                FromZones = ["trust"],
                SourceAddressReferences = ["src-group", "192.168.1.1"],
                ToZones = ["untrust"],
                DestinationAddressReferences = ["dst-host"],
                Applications = ["web-browsing"],
                ServiceReferences = ["svc-group"],
                Action = SecurityPolicyAction.Allow,
                GroupId = "group-a"
            }
        ]);
        var writeSession = new TestWriteRepositorySession();

        var exitCode = ImportUseCase.Execute(
            addressDefinitionReader,
            addressGroupReader,
            serviceDefinitionReader,
            serviceGroupReader,
            securityPolicyReader,
            writeSession);

        Assert.Equal(0, exitCode);

        Assert.Equal([2], writeSession.AddressDefinitionsRepository.AppendBatchSizes);
        Assert.Equal([1], writeSession.AddressGroupsRepository.AppendBatchSizes);
        Assert.Equal([1], writeSession.ServiceDefinitionsRepository.AppendBatchSizes);
        Assert.Equal([1], writeSession.ServiceGroupsRepository.AppendBatchSizes);
        Assert.Equal([1], writeSession.ImportedSecurityPoliciesRepository.AppendBatchSizes);
        Assert.Equal(1, writeSession.AddressDefinitionsRepository.CompleteCount);
        Assert.Equal(1, writeSession.AddressGroupsRepository.CompleteCount);
        Assert.Equal(1, writeSession.ServiceDefinitionsRepository.CompleteCount);
        Assert.Equal(1, writeSession.ServiceGroupsRepository.CompleteCount);
        Assert.Equal(1, writeSession.ImportedSecurityPoliciesRepository.CompleteCount);
        Assert.Equal(0, writeSession.ToolMetadataRepository.ClearCount);
        Assert.Equal(1, writeSession.CommitCount);

        var importedPolicy = Assert.Single(writeSession.ImportedSecurityPoliciesRepository.Items);
        Assert.Equal(["src-group", "192.168.1.1"], importedPolicy.SourceAddressReferences);
        Assert.Equal(["dst-host"], importedPolicy.DestinationAddressReferences);
        Assert.Equal(["svc-group"], importedPolicy.ServiceReferences);
    }
}
