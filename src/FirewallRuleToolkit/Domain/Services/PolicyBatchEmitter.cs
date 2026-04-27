namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// Domain workflow が生成したポリシー batch を外部へ通知する処理です。
/// </summary>
/// <typeparam name="TPolicy">通知対象のポリシー型。</typeparam>
/// <param name="policies">生成されたポリシー batch。</param>
internal delegate void PolicyBatchEmitter<TPolicy>(IReadOnlyList<TPolicy> policies);
