using FluentAssertions;
using Pinotechrd.Security.Tests.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>SECURITY.md is a published contract: its table of known vulnerabilities must name the affected and the fixed versions.</summary>
public class SecurityPolicyDocumentTests
{
    private static IReadOnlyList<string> Rows()
    {
        var text = File.ReadAllText(SessionChangeDetectorTests.RepoFile("SECURITY.md"));
        var section = text[text.IndexOf("## Known Vulnerabilities", StringComparison.Ordinal)..];
        section = section[..section.IndexOf("## Reporting", StringComparison.Ordinal)];
        return section.Split('\n').Where(l => l.TrimStart().StartsWith("| `", StringComparison.Ordinal)).ToList();
    }

    [Fact]
    public void KnownVulnerabilities_ShouldGiveTheAffectedAndTheFixedVersionOnEveryRow()
    {
        var rows = Rows();

        rows.Should().NotBeEmpty();
        rows.Should().OnlyContain(r =>
            (r.Contains("`<= 1.2.0-preview.2`", StringComparison.Ordinal) && r.Contains("`1.2.0-preview.3`", StringComparison.Ordinal))
            || (r.Contains("`<= 1.2.0-preview.3`", StringComparison.Ordinal) && r.Contains("`1.2.0-preview.4`", StringComparison.Ordinal))
            || (r.Contains("`<= 1.2.0-preview.4`", StringComparison.Ordinal) && r.Contains("`1.2.0-preview.5`", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("A bare permission name")]
    [InlineData("merged different ids")]
    [InlineData("authenticated by an endpoint's own scheme")]
    public void KnownVulnerabilities_ShouldListTheThreeIssuesAddedLate(string text)
    {
        Rows().Should().ContainSingle(r => r.Contains(text, StringComparison.Ordinal));
    }

    [Fact]
    public void Supported_Versions_ShouldNameTheLatestPreviewAndRefuseOlderOnes()
    {
        var text = File.ReadAllText(SessionChangeDetectorTests.RepoFile("SECURITY.md"));

        text.Should().Contain("| Latest 1.2.0 preview | Yes |");
        text.Should().Contain("| Older previews | No |");
        text.Should().Contain("Upgrade to `1.2.0-preview.5` or later");
    }
}
