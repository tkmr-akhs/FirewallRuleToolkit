namespace FirewallRuleToolkit.App.UseCases;

/// <summary>
/// import サブコマンドの処理を提供します。
/// </summary>
internal static class ImportUseCase
{
    /// <summary>
    /// CSV からデータベースへ各種定義とポリシーを読み込みます。
    /// </summary>
    public static int Execute(
        IReadRepository<AddressDefinition> addressDefinitionReader,
        IReadRepository<AddressGroupMembership> addressGroupReader,
        IReadRepository<ServiceDefinition> serviceDefinitionReader,
        IReadRepository<ServiceGroupMembership> serviceGroupReader,
        IReadRepository<ImportedSecurityPolicy> securityPolicyReader,
        IWriteRepositorySession writeSession)
    {
        ArgumentNullException.ThrowIfNull(addressDefinitionReader);
        ArgumentNullException.ThrowIfNull(addressGroupReader);
        ArgumentNullException.ThrowIfNull(serviceDefinitionReader);
        ArgumentNullException.ThrowIfNull(serviceGroupReader);
        ArgumentNullException.ThrowIfNull(securityPolicyReader);
        ArgumentNullException.ThrowIfNull(writeSession);

        addressDefinitionReader.EnsureAvailable();
        addressGroupReader.EnsureAvailable();
        serviceDefinitionReader.EnsureAvailable();
        serviceGroupReader.EnsureAvailable();
        securityPolicyReader.EnsureAvailable();

        writeSession.AddressDefinitions.ReplaceAll(addressDefinitionReader.GetAll());
        writeSession.AddressGroups.ReplaceAll(addressGroupReader.GetAll());
        writeSession.ServiceDefinitions.ReplaceAll(serviceDefinitionReader.GetAll());
        writeSession.ServiceGroups.ReplaceAll(serviceGroupReader.GetAll());
        writeSession.ImportedSecurityPolicies.ReplaceAll(securityPolicyReader.GetAll());

        writeSession.AddressDefinitions.Complete();
        writeSession.AddressGroups.Complete();
        writeSession.ServiceDefinitions.Complete();
        writeSession.ServiceGroups.Complete();
        writeSession.ImportedSecurityPolicies.Complete();
        writeSession.Commit();

        return 0;
    }
}
