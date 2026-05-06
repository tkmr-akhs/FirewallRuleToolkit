namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// small well-known destination ports 条件を判定します。
/// </summary>
internal sealed class SmallWellKnownDestinationPortMatcher
{
    /// <summary>
    /// 条件判定に使う well-known 宛先ポート集合です。
    /// </summary>
    private readonly HashSet<uint> wellKnownDestinationPorts;

    /// <summary>
    /// small とみなすポート種類数の上限です。
    /// </summary>
    private readonly uint smallWellKnownDestinationPortCountThreshold;

    /// <summary>
    /// small well-known destination ports 条件を判定するクラスのコンストラクターです。
    /// </summary>
    /// <param name="wellKnownDestinationPorts">対象ポート集合。</param>
    /// <param name="smallWellKnownDestinationPortCountThreshold">small とみなす宛先ポート種類数のしきい値。</param>
    public SmallWellKnownDestinationPortMatcher(
        IReadOnlySet<uint>? wellKnownDestinationPorts,
        uint? smallWellKnownDestinationPortCountThreshold)
    {
        this.wellKnownDestinationPorts = wellKnownDestinationPorts is null
            ? new HashSet<uint>()
            : new HashSet<uint>(wellKnownDestinationPorts);
        this.smallWellKnownDestinationPortCountThreshold = smallWellKnownDestinationPortCountThreshold ?? 0;
    }

    /// <summary>
    /// サービス集合が small well-known destination ports 条件に該当するとき、
    /// 対象ポート一覧を返します。
    /// </summary>
    /// <param name="services">判定対象サービス集合。</param>
    /// <param name="destinationPorts">条件に該当した宛先ポート一覧。</param>
    /// <returns>条件に該当するとき <see langword="true"/>。</returns>
    public bool TryGetSmallWellKnownDestinationPorts(
        IEnumerable<ServiceValue> services,
        out uint[] destinationPorts)
    {
        destinationPorts = [];
        if (wellKnownDestinationPorts.Count == 0 || smallWellKnownDestinationPortCountThreshold == 0)
        {
            return false;
        }

        var ports = new HashSet<uint>();
        foreach (var service in services)
        {
            if (service.DestinationPortStart != service.DestinationPortFinish)
            {
                return false;
            }

            var destinationPort = service.DestinationPortStart;
            if (!wellKnownDestinationPorts.Contains(destinationPort))
            {
                return false;
            }

            ports.Add(destinationPort);
            if (ports.Count >= smallWellKnownDestinationPortCountThreshold)
            {
                return false;
            }
        }

        if (ports.Count == 0)
        {
            return false;
        }

        destinationPorts = [.. ports.OrderBy(static port => port)];
        return true;
    }
}
