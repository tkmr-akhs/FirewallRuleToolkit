namespace FirewallRuleToolkit.App.UseCases;

/// <summary>
/// import サブコマンドの処理を提供します。
/// </summary>
internal static class ImportUseCase
{
    /// <summary>
    /// CSV からデータベースへ各種オブジェクトとポリシーを読み込みます。
    /// </summary>
    public static int Execute(
        IReadRepository<AddressObject> addressObjectReader,
        IReadRepository<AddressGroupMembership> addressGroupReader,
        IReadRepository<ServiceObject> serviceObjectReader,
        IReadRepository<ServiceGroupMembership> serviceGroupReader,
        IReadRepository<ImportedSecurityPolicy> securityPolicyReader,
        IWriteRepositorySession writeSession)
    {
        ArgumentNullException.ThrowIfNull(addressObjectReader);
        ArgumentNullException.ThrowIfNull(addressGroupReader);
        ArgumentNullException.ThrowIfNull(serviceObjectReader);
        ArgumentNullException.ThrowIfNull(serviceGroupReader);
        ArgumentNullException.ThrowIfNull(securityPolicyReader);
        ArgumentNullException.ThrowIfNull(writeSession);

        addressObjectReader.EnsureAvailable();
        addressGroupReader.EnsureAvailable();
        serviceObjectReader.EnsureAvailable();
        serviceGroupReader.EnsureAvailable();
        securityPolicyReader.EnsureAvailable();

        writeSession.AddressObjects.ReplaceAll(addressObjectReader.GetAll());
        writeSession.AddressGroups.ReplaceAll(addressGroupReader.GetAll());
        writeSession.ServiceObjects.ReplaceAll(serviceObjectReader.GetAll());
        writeSession.ServiceGroups.ReplaceAll(serviceGroupReader.GetAll());
        writeSession.ImportedSecurityPolicies.ReplaceAll(securityPolicyReader.GetAll());

        writeSession.AddressObjects.Complete();
        writeSession.AddressGroups.Complete();
        writeSession.ServiceObjects.Complete();
        writeSession.ServiceGroups.Complete();
        writeSession.ImportedSecurityPolicies.Complete();
        writeSession.Commit();

        return 0;
    }
}
