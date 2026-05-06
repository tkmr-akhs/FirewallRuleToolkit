namespace FirewallRuleToolkit.Domain.ValueObjects;

/// <summary>
/// サービス値の範囲を表します。
/// </summary>
public readonly struct ServiceValue
{
    /// <summary>
    /// IP プロトコル番号の開始値を取得します。
    /// </summary>
    public uint ProtocolStart { get; init; }

    /// <summary>
    /// IP プロトコル番号の終了値を取得します。
    /// </summary>
    public uint ProtocolFinish { get; init; }

    /// <summary>
    /// 送信元ポートの開始値を取得します。
    /// </summary>
    public uint SourcePortStart { get; init; }

    /// <summary>
    /// 送信元ポートの終了値を取得します。
    /// </summary>
    public uint SourcePortFinish { get; init; }

    /// <summary>
    /// 宛先ポートの開始値を取得します。
    /// </summary>
    public uint DestinationPortStart { get; init; }

    /// <summary>
    /// 宛先ポートの終了値を取得します。
    /// </summary>
    public uint DestinationPortFinish { get; init; }

    /// <summary>
    /// サービスの種別を取得します。
    /// </summary>
    public string? Kind { get; init; }
}
