namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// 高一致率な Allow ルールを共通部と残差へ再編成します。
/// </summary>
internal sealed class HighSimilarityPolicyRecomposer
{
    /// <summary>
    /// 共通サービスの well-known 条件判定を行います。
    /// </summary>
    private readonly SmallWellKnownDestinationPortMatcher smallWellKnownDestinationPortMatcher;

    /// <summary>
    /// 高一致率再編成で必要な一致率です。
    /// </summary>
    private readonly uint highSimilarityThresholdPercentage;

    /// <summary>
    /// デバッグ ログ出力先です。
    /// </summary>
    private readonly ILogger logger;

    /// <summary>
    /// 高一致率な Allow ルールを共通部と残差へ再編成するクラスのコンストラクターです。
    /// </summary>
    /// <param name="smallWellKnownDestinationPortMatcher">well-known 条件判定。</param>
    /// <param name="highSimilarityThresholdPercentage">高一致率再編成に使う類似度しきい値 (パーセント)。</param>
    /// <param name="logger">デバッグ ログ出力先。</param>
    public HighSimilarityPolicyRecomposer(
        SmallWellKnownDestinationPortMatcher smallWellKnownDestinationPortMatcher,
        uint highSimilarityThresholdPercentage,
        ILogger? logger = null)
    {
        this.smallWellKnownDestinationPortMatcher = smallWellKnownDestinationPortMatcher
            ?? throw new ArgumentNullException(nameof(smallWellKnownDestinationPortMatcher));
        this.highSimilarityThresholdPercentage = ValidateHighSimilarityThresholdPercentage(
            highSimilarityThresholdPercentage);
        this.logger = logger.OrNullLogger();
    }

    /// <summary>
    /// 3 パス後の Allow 候補群を、高一致率な 2 ルール単位で再編成します。
    /// </summary>
    /// <param name="policies">3 パス完了後の Allow 候補列。</param>
    /// <returns>再編成後の候補列。</returns>
    public IReadOnlyList<MergedSecurityPolicy> Recompose(IReadOnlyList<MergedSecurityPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);

        var mutablePolicies = policies
            .Select(MutableMergedSecurityPolicy.FromMergedSecurityPolicy)
            .ToArray();

        return RecomposeMutable(mutablePolicies)
            .Select(static policy => policy.ToMergedSecurityPolicy())
            .ToArray();
    }

    /// <summary>
    /// 3 パス後の Allow 候補群を、可変候補のまま高一致率な 2 ルール単位で再編成します。
    /// </summary>
    /// <param name="policies">3 パス完了後の可変 Allow 候補列。</param>
    /// <returns>再編成後の可変候補列。</returns>
    internal IReadOnlyList<MutableMergedSecurityPolicy> RecomposeMutable(IReadOnlyList<MutableMergedSecurityPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        if (policies.Count < 2)
        {
            return [.. policies];
        }

        return policies
            .GroupBy(CreateRecompositionSignature, StringComparer.Ordinal)
            .SelectMany(group => RecomposeGroup([.. group]))
            .ToArray();
    }

    /// <summary>
    /// 高一致率再編成の比較グループ識別シグネチャを生成します。
    /// </summary>
    /// <param name="policy">シグネチャ生成対象の候補。</param>
    /// <returns>再編成比較グループ用のシグネチャ。</returns>
    private static string CreateRecompositionSignature(MutableMergedSecurityPolicy policy)
    {
        return string.Concat(
            "fz=", MergeSignatureBuilder.OrdinalStringSet(policy.FromZones),
            "|tz=", MergeSignatureBuilder.OrdinalStringSet(policy.ToZones),
            "|ap=", MergeSignatureBuilder.ApplicationConfiguredIdentitySet(policy.Applications),
            "|ac=", policy.Action,
            "|gid=", MergeSignatureBuilder.OrdinalStringValue(policy.GroupId));
    }

    /// <summary>
    /// 同一比較グループ内で、高一致率ペアの再編成を繰り返します。
    /// </summary>
    /// <param name="policies">再編成対象グループ。</param>
    /// <returns>再編成後の候補列。</returns>
    private List<MutableMergedSecurityPolicy> RecomposeGroup(IReadOnlyList<MutableMergedSecurityPolicy> policies)
    {
        // 具体例
        //
        // Left
        //   Source = {L}
        //   Destination = {A, B}
        //   Service = {80, 443}
        // Right
        //   Source = {R}
        //   Destination = {B, C}
        //   Service = {80, 8080}
        //
        // このとき
        //   commonDestinationAddresses = {B}
        //   commonServices = {80}
        //   unionSources = {L, R}
        // になります。
        //
        // 作られるルールはこうです。
        //
        // 共通部 (LRの和 -> LRの共通部: LRの共通部)
        //   {L, R} × {B} × {80}
        // Left の宛先差分残差 (L -> Lの残り : L)
        //   {L} × {A} × {80, 443}
        // Left のサービス差分残差 (L -> LRの共通部 : Lの残り)
        //   {L} × {B} × {443}
        // Right の宛先差分残差 (R -> Rの残り : R)
        //   {R} × {C} × {80, 8080}
        // Right のサービス差分残差 (R -> LRの共通部 : Rの残り)
        //   {R} × {B} × {8080}

        LogHighSimilarityGroupStart(policies);

        var activePolicies = policies.ToList();
        var settledPolicies = new List<MutableMergedSecurityPolicy>();

        while (activePolicies.Count >= 2)
        {
            var bestPair = FindBestHighSimilarityPair(activePolicies);
            if (bestPair is null)
            {
                break;
            }

            var pair = bestPair.Value;
            var left = activePolicies[pair.LeftIndex];
            var right = activePolicies[pair.RightIndex];

            LogHighSimilarityPairSelected(left, right, pair);

            activePolicies.RemoveAt(pair.RightIndex);
            activePolicies.RemoveAt(pair.LeftIndex);

            var leftResiduals = CreateResidualPolicies(
                left,
                pair.CommonDestinationAddresses,
                pair.CommonServices)
                .ToArray();
            var rightResiduals = CreateResidualPolicies(
                right,
                pair.CommonDestinationAddresses,
                pair.CommonServices)
                .ToArray();
            var commonPolicy = CreateCommonPolicy(
                left,
                right,
                pair.UnionSourceAddresses,
                pair.CommonDestinationAddresses,
                pair.CommonServices);

            LogHighSimilarityPairRecomposed(
                left,
                right,
                commonPolicy,
                leftResiduals.Length + rightResiduals.Length);

            settledPolicies.AddRange(leftResiduals);
            settledPolicies.AddRange(rightResiduals);
            activePolicies.Add(commonPolicy);
        }

        LogHighSimilarityGroupCompleted(settledPolicies.Count, activePolicies.Count);

        settledPolicies.AddRange(activePolicies);
        return settledPolicies;
    }

    /// <summary>
    /// 候補群から、宛先アドレスとサービスの共通要素数がもっとも多い有効ペアを選びます。
    /// </summary>
    /// <param name="policies">評価対象の候補群。</param>
    /// <returns>有効ペアがある場合はその情報。なければ <see langword="null"/>。</returns>
    private HighSimilarityPairCandidate? FindBestHighSimilarityPair(
        IReadOnlyList<MutableMergedSecurityPolicy> policies)
    {
        HighSimilarityPairCandidate? bestPair = null;

        for (var leftIndex = 0; leftIndex < policies.Count - 1; leftIndex++)
        {
            var left = policies[leftIndex];

            for (var rightIndex = leftIndex + 1; rightIndex < policies.Count; rightIndex++)
            {
                var right = policies[rightIndex];

                var commonDestinationAddresses = AddressConditionSetOperations.IntersectByConfiguredIdentity(left.DestinationAddresses, right.DestinationAddresses);
                if (!MeetsHighSimilarityThreshold(commonDestinationAddresses.Count, left.DestinationAddresses.Count, right.DestinationAddresses.Count))
                {
                    continue;
                }

                var commonServices = ServiceConditionSetOperations.IntersectByConfiguredIdentity(left.Services, right.Services);
                if (!MeetsHighSimilarityThreshold(commonServices.Count, left.Services.Count, right.Services.Count))
                {
                    continue;
                }

                var unionSourceAddresses = AddressConditionSetOperations.UnionByConfiguredIdentity(left.SourceAddresses, right.SourceAddresses);

                if (smallWellKnownDestinationPortMatcher.TryGetSmallWellKnownDestinationPorts(commonServices, out var destinationPorts))
                {
                    LogHighSimilarityPairSkippedDueToWellKnownPorts(left, right, destinationPorts);
                    continue;
                }

                var score = commonDestinationAddresses.Count + commonServices.Count;
                if (bestPair is null || score > bestPair.Value.Score)
                {
                    bestPair = new HighSimilarityPairCandidate(
                        leftIndex,
                        rightIndex,
                        score,
                        unionSourceAddresses,
                        commonDestinationAddresses,
                        commonServices);
                }
            }
        }

        return bestPair;
    }

    /// <summary>
    /// 再編成用の共通部ルールを作成します。
    /// </summary>
    /// <param name="left">左側候補。</param>
    /// <param name="right">右側候補。</param>
    /// <param name="unionSourceAddresses">共通部へ設定する送信元 Union。</param>
    /// <param name="commonDestinationAddresses">共通宛先。</param>
    /// <param name="commonServices">共通サービス。</param>
    /// <returns>共通部ルール。</returns>
    private static MutableMergedSecurityPolicy CreateCommonPolicy(
        MutableMergedSecurityPolicy left,
        MutableMergedSecurityPolicy right,
        HashSet<AddressValue> unionSourceAddresses,
        HashSet<AddressValue> commonDestinationAddresses,
        HashSet<ServiceValue> commonServices)
    {
        var originalPolicyNames = new HashSet<string>(left.OriginalPolicyNames, StringComparer.Ordinal);
        originalPolicyNames.UnionWith(right.OriginalPolicyNames);

        return MergedSecurityPolicyFactory.CreateFromTemplate(
            left,
            unionSourceAddresses,
            commonDestinationAddresses,
            commonServices,
            Math.Min(left.MinimumIndex, right.MinimumIndex),
            Math.Max(left.MaximumIndex, right.MaximumIndex),
            originalPolicyNames);
    }

    /// <summary>
    /// 再編成後の残差ルールを順番どおり生成します。
    /// </summary>
    /// <param name="template">残差の元になった候補。</param>
    /// <param name="commonDestinationAddresses">共通宛先。</param>
    /// <param name="commonServices">共通サービス。</param>
    /// <returns>空でない残差ルール列。</returns>
    private static IEnumerable<MutableMergedSecurityPolicy> CreateResidualPolicies(
        MutableMergedSecurityPolicy template,
        HashSet<AddressValue> commonDestinationAddresses,
        HashSet<ServiceValue> commonServices)
    {
        var destinationDifference = AddressConditionSetOperations.SubtractByConfiguredIdentity(template.DestinationAddresses, commonDestinationAddresses);
        if (destinationDifference.Count > 0)
        {
            yield return MergedSecurityPolicyFactory.CreateFromTemplate(
                template,
                template.SourceAddresses,
                destinationDifference,
                template.Services,
                template.MinimumIndex,
                template.MaximumIndex,
                template.OriginalPolicyNames);
        }

        var serviceDifference = ServiceConditionSetOperations.SubtractByConfiguredIdentity(template.Services, commonServices);
        if (serviceDifference.Count > 0)
        {
            yield return MergedSecurityPolicyFactory.CreateFromTemplate(
                template,
                template.SourceAddresses,
                commonDestinationAddresses,
                serviceDifference,
                template.MinimumIndex,
                template.MaximumIndex,
                template.OriginalPolicyNames);
        }
    }

    /// <summary>
    /// 指定割合の一致条件を整数演算で判定します。
    /// </summary>
    /// <param name="commonCount">共通要素数。</param>
    /// <param name="leftCount">左側要素数。</param>
    /// <param name="rightCount">右側要素数。</param>
    /// <returns>左右とも指定割合以上なら <see langword="true"/>。</returns>
    private bool MeetsHighSimilarityThreshold(
        int commonCount,
        int leftCount,
        int rightCount)
    {
        return commonCount > 0
            && ((ulong)commonCount * 100) >= ((ulong)leftCount * highSimilarityThresholdPercentage)
            && ((ulong)commonCount * 100) >= ((ulong)rightCount * highSimilarityThresholdPercentage);
    }

    /// <summary>
    /// 高一致率再編成に使うしきい値の妥当性を検証します。
    /// </summary>
    /// <param name="highSimilarityThresholdPercentage">検証対象のしきい値。</param>
    /// <returns>検証済みのしきい値。</returns>
    private static uint ValidateHighSimilarityThresholdPercentage(uint highSimilarityThresholdPercentage)
    {
        if (highSimilarityThresholdPercentage is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(highSimilarityThresholdPercentage),
                highSimilarityThresholdPercentage,
                "High similarity threshold percentage must be between 1 and 100.");
        }

        return highSimilarityThresholdPercentage;
    }

    /// <summary>
    /// 高一致率再編成グループの開始をデバッグ ログへ出力します。
    /// </summary>
    /// <param name="policies">対象グループ。</param>
    private void LogHighSimilarityGroupStart(IReadOnlyList<MutableMergedSecurityPolicy> policies)
    {
        if (policies.Count == 0)
        {
            return;
        }

        var sample = policies[0];
        logger.LogDebugIfEnabled(log =>
            log.LogDebug(
                "merge debug: start high-similarity recomposition. policyCount={PolicyCount}, fromZones={FromZones}, toZones={ToZones}, applications={Applications}, action={Action}, groupId={GroupId}",
                policies.Count,
                FormatStringValues(sample.FromZones),
                FormatStringValues(sample.ToZones),
                FormatStringValues(sample.Applications),
                sample.Action,
                sample.GroupId));
    }

    /// <summary>
    /// 高一致率再編成グループの完了をデバッグ ログへ出力します。
    /// </summary>
    /// <param name="settledPolicyCount">確定済み残差数。</param>
    /// <param name="remainingPolicyCount">未再編成で残った候補数。</param>
    private void LogHighSimilarityGroupCompleted(
        int settledPolicyCount,
        int remainingPolicyCount)
    {
        logger.LogDebugIfEnabled(log =>
            log.LogDebug(
                "merge debug: completed high-similarity recomposition. settledPolicies={SettledPolicyCount}, remainingPolicies={RemainingPolicyCount}",
                settledPolicyCount,
                remainingPolicyCount));
    }

    /// <summary>
    /// 選択された高一致率ペアをデバッグ ログへ出力します。
    /// </summary>
    /// <param name="left">左側候補。</param>
    /// <param name="right">右側候補。</param>
    /// <param name="pair">選択されたペア情報。</param>
    private void LogHighSimilarityPairSelected(
        MutableMergedSecurityPolicy left,
        MutableMergedSecurityPolicy right,
        HighSimilarityPairCandidate pair)
    {
        logger.LogDebugIfEnabled(log =>
            log.LogDebug(
                "merge debug: selected high-similarity pair. score={Score}, unionSources={UnionSourceCount}, commonDestinations={CommonDestinationCount}, commonServices={CommonServiceCount}, leftRange=[{LeftMinimumIndex}-{LeftMaximumIndex}], rightRange=[{RightMinimumIndex}-{RightMaximumIndex}], leftOriginalNames={LeftOriginalNames}, rightOriginalNames={RightOriginalNames}",
                pair.Score,
                pair.UnionSourceAddresses.Count,
                pair.CommonDestinationAddresses.Count,
                pair.CommonServices.Count,
                left.MinimumIndex,
                left.MaximumIndex,
                right.MinimumIndex,
                right.MaximumIndex,
                FormatStringValues(left.OriginalPolicyNames),
                FormatStringValues(right.OriginalPolicyNames)));
    }

    /// <summary>
    /// 高一致率ペアの再編成結果をデバッグ ログへ出力します。
    /// </summary>
    /// <param name="left">左側候補。</param>
    /// <param name="right">右側候補。</param>
    /// <param name="commonPolicy">生成した共通部。</param>
    /// <param name="residualCount">生成した残差数。</param>
    private void LogHighSimilarityPairRecomposed(
        MutableMergedSecurityPolicy left,
        MutableMergedSecurityPolicy right,
        MutableMergedSecurityPolicy commonPolicy,
        int residualCount)
    {
        logger.LogDebugIfEnabled(log =>
            log.LogDebug(
                "merge debug: created recomposed policies. residualCount={ResidualCount}, commonRange=[{CommonMinimumIndex}-{CommonMaximumIndex}], leftOriginalNames={LeftOriginalNames}, rightOriginalNames={RightOriginalNames}, commonOriginalNames={CommonOriginalNames}",
                residualCount,
                commonPolicy.MinimumIndex,
                commonPolicy.MaximumIndex,
                FormatStringValues(left.OriginalPolicyNames),
                FormatStringValues(right.OriginalPolicyNames),
                FormatStringValues(commonPolicy.OriginalPolicyNames)));
    }

    /// <summary>
    /// well-known port 条件で再編成対象から外したペアをデバッグ ログへ出力します。
    /// </summary>
    /// <param name="left">左側候補。</param>
    /// <param name="right">右側候補。</param>
    /// <param name="destinationPorts">該当した宛先ポート一覧。</param>
    private void LogHighSimilarityPairSkippedDueToWellKnownPorts(
        MutableMergedSecurityPolicy left,
        MutableMergedSecurityPolicy right,
        IReadOnlyList<uint> destinationPorts)
    {
        logger.LogDebugIfEnabled(log =>
            log.LogDebug(
                "merge debug: skipped high-similarity pair because common services are small well-known destination ports. leftRange=[{LeftMinimumIndex}-{LeftMaximumIndex}], rightRange=[{RightMinimumIndex}-{RightMaximumIndex}], destinationPorts={DestinationPorts}",
                left.MinimumIndex,
                left.MaximumIndex,
                right.MinimumIndex,
                right.MaximumIndex,
                FormatUIntValues(destinationPorts)));
    }

    /// <summary>
    /// 数値列をログ向けのカンマ区切り文字列へ変換します。
    /// </summary>
    /// <param name="values">対象値列。</param>
    /// <returns>ログ向け文字列。</returns>
    private static string FormatUIntValues(IEnumerable<uint> values)
    {
        return string.Join(",", values.OrderBy(static value => value));
    }

    /// <summary>
    /// 文字列列をログ向けのカンマ区切り文字列へ変換します。
    /// </summary>
    /// <param name="values">対象値列。</param>
    /// <returns>ログ向け文字列。</returns>
    private static string FormatStringValues(IEnumerable<string> values)
    {
        return string.Join(",", PolicyConditionCanonicalOrder.OrderOrdinalStrings(values));
    }

    /// <summary>
    /// 高一致率再編成の最良ペア情報です。
    /// </summary>
    /// <param name="LeftIndex">左側候補インデックス。</param>
    /// <param name="RightIndex">右側候補インデックス。</param>
    /// <param name="Score">共通宛先数と共通サービス数の合計。</param>
    /// <param name="UnionSourceAddresses">共通部へ設定する送信元 Union。</param>
    /// <param name="CommonDestinationAddresses">共通宛先。</param>
    /// <param name="CommonServices">共通サービス。</param>
    private readonly record struct HighSimilarityPairCandidate(
        int LeftIndex,
        int RightIndex,
        int Score,
        HashSet<AddressValue> UnionSourceAddresses,
        HashSet<AddressValue> CommonDestinationAddresses,
        HashSet<ServiceValue> CommonServices);
}
