using FirewallRuleToolkit.App.UseCases;
using FirewallRuleToolkit.Config;
using FirewallRuleToolkit.Logging;
using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Enums;
using FirewallRuleToolkit.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace FirewallRuleToolkit.Tests.App;

[Collection("ProgramLogger")]
public sealed class TestUseCaseTests
{
    [Fact]
    public void Execute_WhenMergedAnyApplicationCoversShadowedSpecificApplication_LogsOnlyRemainingWarning()
    {
        var source = new TestAtomicPolicyMergeSource(
        [
            CreateAtomicPolicy(
                originalIndex: 10,
                originalPolicyName: "front-policy",
                application: "any",
                sourceStart: 1,
                sourceFinish: 10,
                destinationStart: 100,
                destinationFinish: 100,
                destinationPortStart: 80,
                destinationPortFinish: 90),
            CreateAtomicPolicy(
                originalIndex: 11,
                originalPolicyName: "shadowed-policy",
                application: "web-browsing",
                sourceStart: 3,
                sourceFinish: 3,
                destinationStart: 100,
                destinationFinish: 100,
                destinationPortStart: 80,
                destinationPortFinish: 80),
            CreateAtomicPolicy(
                originalIndex: 20,
                originalPolicyName: "missing-policy",
                fromZone: "dmz",
                toZone: "wan",
                sourceStart: 200,
                sourceFinish: 200,
                destinationStart: 300,
                destinationFinish: 300,
                destinationPortStart: 443,
                destinationPortFinish: 443)
        ]);
        var merged = new TestReadRepository<MergedSecurityPolicy>(
        [
            CreateMergedPolicy(
                minimumIndex: 10,
                maximumIndex: 11,
                application: "any",
                sourceStart: 1,
                sourceFinish: 10,
                destinationStart: 100,
                destinationFinish: 100,
                destinationPortStart: 80,
                destinationPortFinish: 90)
        ]);

        var logText = CaptureInformationLog(() =>
        {
            var exitCode = TestUseCase.Execute(source, merged);
            Assert.Equal(0, exitCode);
        });

        Assert.True(source.EnsureAvailableCalled);
        Assert.True(merged.EnsureAvailableCalled);
        Assert.Contains("test warning: atomic policy is not represented in merged output.", logText, StringComparison.Ordinal);
        Assert.Contains("policy=missing-policy", logText, StringComparison.Ordinal);
        Assert.DoesNotContain("test info: shadowed atomic policy is not directly represented in merged output.", logText, StringComparison.Ordinal);
        Assert.DoesNotContain("policy=shadowed-policy", logText, StringComparison.Ordinal);
        Assert.Contains("test completed. atomicProcessed: 3, nonShadowedChecked: 2, shadowedChecked: 1, warnings: 1, informationals: 0", logText, StringComparison.Ordinal);
    }

    private static string CaptureInformationLog(Action action)
    {
        var logPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.log");

        try
        {
            ProgramLogger.Dispose();
            _ = ProgramLogger.GetLogger(LogType.File, logPath, LogLevel.Information);

            action();

            ProgramLogger.Dispose();
            return File.Exists(logPath)
                ? ReadAllTextShared(logPath)
                : string.Empty;
        }
        finally
        {
            ProgramLogger.Dispose();

            if (File.Exists(logPath))
            {
                try
                {
                    File.Delete(logPath);
                }
                catch (IOException)
                {
                }
            }
        }
    }

    private static string ReadAllTextShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static AtomicSecurityPolicy CreateAtomicPolicy(
        ulong originalIndex,
        string originalPolicyName,
        SecurityPolicyAction action = SecurityPolicyAction.Allow,
        string application = "web-browsing",
        string fromZone = "trust",
        string toZone = "untrust",
        uint sourceStart = 1,
        uint sourceFinish = 1,
        uint destinationStart = 100,
        uint destinationFinish = 100,
        uint destinationPortStart = 80,
        uint destinationPortFinish = 80)
    {
        return new AtomicSecurityPolicy
        {
            FromZone = fromZone,
            SourceAddress = new AddressValue { Start = sourceStart, Finish = sourceFinish },
            ToZone = toZone,
            DestinationAddress = new AddressValue { Start = destinationStart, Finish = destinationFinish },
            Application = application,
            Service = new ServiceValue
            {
                ProtocolStart = 6,
                ProtocolFinish = 6,
                SourcePortStart = 0,
                SourcePortFinish = 65535,
                DestinationPortStart = destinationPortStart,
                DestinationPortFinish = destinationPortFinish,
                Kind = "service"
            },
            Action = action,
            GroupId = "group-1",
            OriginalIndex = originalIndex,
            OriginalPolicyName = originalPolicyName
        };
    }

    private static MergedSecurityPolicy CreateMergedPolicy(
        ulong minimumIndex,
        ulong maximumIndex,
        SecurityPolicyAction action = SecurityPolicyAction.Allow,
        string application = "web-browsing",
        string fromZone = "trust",
        string toZone = "untrust",
        uint sourceStart = 1,
        uint sourceFinish = 1,
        uint destinationStart = 100,
        uint destinationFinish = 100,
        uint destinationPortStart = 80,
        uint destinationPortFinish = 80)
    {
        return new MergedSecurityPolicy
        {
            FromZones = new HashSet<string>(StringComparer.Ordinal) { fromZone },
            SourceAddresses = [new AddressValue { Start = sourceStart, Finish = sourceFinish }],
            ToZones = new HashSet<string>(StringComparer.Ordinal) { toZone },
            DestinationAddresses = [new AddressValue { Start = destinationStart, Finish = destinationFinish }],
            Applications = new HashSet<string>(StringComparer.Ordinal) { application },
            Services =
            [
                new ServiceValue
                {
                    ProtocolStart = 6,
                    ProtocolFinish = 6,
                    SourcePortStart = 0,
                    SourcePortFinish = 65535,
                    DestinationPortStart = destinationPortStart,
                    DestinationPortFinish = destinationPortFinish,
                    Kind = "service"
                }
            ],
            Action = action,
            GroupId = "group-merged",
            MinimumIndex = minimumIndex,
            MaximumIndex = maximumIndex,
            OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { $"merged-{minimumIndex}" }
        };
    }
}
