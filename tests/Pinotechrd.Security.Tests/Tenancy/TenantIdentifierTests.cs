using FluentAssertions;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Tenancy;

public class TenantIdentifierTests
{
    public static TheoryData<string?> InvalidIds() =>
    [
        null,
        "",
        new string('a', 57),
        "Tenant-A",
        "ABC",
        "a_b",
        "a b",
        " a",
        "a.b",
        "a/b",
        "a\\b",
        "tenant-é",
        "中文",
        "a\u0001b",
        "a\nb",
        "a\0b",
        "-abc",
        "-",
        "a;drop table x",
        "a\"b",
        "a'b"
    ];

    [Theory]
    [MemberData(nameof(InvalidIds))]
    public void IsValid_ShouldRejectMalformedIds(string? id)
    {
        TenantIdentifier.IsValid(id).Should().BeFalse();
    }

    [Theory]
    [InlineData("a")]
    [InlineData("0")]
    [InlineData("a-b")]
    [InlineData("abc-")]
    [InlineData("demo")]
    [InlineData("3f2504e0-4f89-11d3-9a0c-0305e82c3301")]
    public void IsValid_ShouldAcceptLowerCaseDigitsAndHyphens(string id)
    {
        TenantIdentifier.IsValid(id).Should().BeTrue();
    }

    [Fact]
    public void IsValid_ShouldAccept56CharactersAndReject57()
    {
        TenantIdentifier.IsValid(new string('a', 56)).Should().BeTrue();
        TenantIdentifier.IsValid(new string('a', 57)).Should().BeFalse();
        TenantIdentifier.IsValid("a" + new string('-', 55)).Should().BeTrue();
    }

    [Fact]
    public void ToSchemaName_ShouldPrefixAndReplaceHyphens()
    {
        TenantIdentifier.ToSchemaName("a-b").Should().Be("tenant_a_b");
        TenantIdentifier.ToSchemaName("demo").Should().Be("tenant_demo");
    }

    [Theory]
    [MemberData(nameof(InvalidIds))]
    public void ToSchemaName_ShouldThrowArgumentException_ForInvalidIds(string? id)
    {
        var act = () => TenantIdentifier.ToSchemaName(id!);

        act.Should().Throw<ArgumentException>();
    }

    [Theory]
    [MemberData(nameof(InvalidIds))]
    public void SetTenant_ShouldThrowArgumentExceptionAndKeepNoTenant_ForInvalidIds(string? id)
    {
        var context = new TenantContext();

        var act = () => context.SetTenant(id!);

        act.Should().Throw<ArgumentException>();
        context.TenantId.Should().BeNull();
        context.SchemaName.Should().BeNull();
    }

    [Fact]
    public void SetTenant_ShouldExposeTheSchema_ForAValidId()
    {
        var context = new TenantContext();

        context.SetTenant("acme-1");

        context.TenantId.Should().Be("acme-1");
        context.SchemaName.Should().Be("tenant_acme_1");
    }

    [Fact]
    public void ToSchemaName_ShouldNeverExceed63Characters_ForTheLongestId()
    {
        TenantIdentifier.ToSchemaName(new string('a', 56)).Length.Should().Be(63);
        TenantIdentifier.ToSchemaName("a" + new string('-', 55)).Length.Should().Be(63);
    }

    [Fact]
    public void ToSchemaName_ShouldNotMapTwoDifferentExhaustiveIdsToTheSameSchema()
    {
        // Every id of length 1 to 4 over a small alphabet that includes the hyphen.
        const string alphabet = "ab0-";
        var ids = new List<string>();
        for (var length = 1; length <= 4; length++)
        {
            var count = (int)Math.Pow(alphabet.Length, length);
            for (var n = 0; n < count; n++)
            {
                var chars = new char[length];
                var rest = n;
                for (var i = 0; i < length; i++)
                {
                    chars[i] = alphabet[rest % alphabet.Length];
                    rest /= alphabet.Length;
                }
                ids.Add(new string(chars));
            }
        }

        var valid = ids.Where(TenantIdentifier.IsValid).ToList();
        var schemas = valid.Select(TenantIdentifier.ToSchemaName).ToList();

        valid.Should().NotBeEmpty();
        schemas.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void ToSchemaName_ShouldKeepIdsThatDifferOnlyByHyphenPositionApart()
    {
        var ids = new[] { "a-bc", "ab-c", "abc-", "a--b", "a-b-", "ab--", "a-b-c" };

        var schemas = ids.Select(TenantIdentifier.ToSchemaName).ToList();

        schemas.Should().OnlyHaveUniqueItems();
        schemas.Should().Equal("tenant_a_bc", "tenant_ab_c", "tenant_abc_", "tenant_a__b", "tenant_a_b_", "tenant_ab__", "tenant_a_b_c");
    }

    [Fact]
    public void ToSchemaName_ShouldBeInjectiveAndReversible_ForManyRandomValidIds()
    {
        var random = new Random(12345);
        const string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-";
        var seen = new Dictionary<string, string>();

        for (var i = 0; i < 20_000; i++)
        {
            var length = random.Next(1, 57);
            var chars = new char[length];
            for (var c = 0; c < length; c++) chars[c] = alphabet[random.Next(alphabet.Length)];
            if (chars[0] == '-') chars[0] = 'x';
            var id = new string(chars);

            var schema = TenantIdentifier.ToSchemaName(id);

            schema.Length.Should().BeLessThanOrEqualTo(63);
            schema.Should().StartWith("tenant_");
            schema.Should().MatchRegex("^[a-z0-9_]+$");
            schema["tenant_".Length..].Replace('_', '-').Should().Be(id);
            if (seen.TryGetValue(schema, out var other)) other.Should().Be(id, "one schema must belong to one id");
            seen[schema] = id;
        }
    }

    // ---- DbSchemaProvider --------------------------------------------------------------------

    [Fact]
    public void DbSchemaProvider_ShouldThrowInvalidOperation_WhenNoTenantIsResolved()
    {
        var provider = new DbSchemaProvider(new TenantContext());

        var act = () => provider.GetSchemaName();

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void DbSchemaProvider_ShouldThrowInvalidOperation_WhenNoTenantAndTheSharedSchemaOptionIsOff()
    {
        var provider = new DbSchemaProvider(new TenantContext(), new TenantResolutionOptions { UseSharedSchemaWhenNoTenant = false });

        var act = () => provider.GetSchemaName();

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void DbSchemaProvider_ShouldReturnTheSharedSchema_WhenNoTenantAndTheOptionIsOn()
    {
        var provider = new DbSchemaProvider(new TenantContext(), new TenantResolutionOptions { UseSharedSchemaWhenNoTenant = true });

        provider.GetSchemaName().Should().Be("identity");
    }

    [Fact]
    public void DbSchemaProvider_ShouldReturnTheTenantSchema_EvenWhenTheSharedSchemaOptionIsOn()
    {
        var tenant = new TenantContext();
        tenant.SetTenant("acme-1");
        var provider = new DbSchemaProvider(tenant, new TenantResolutionOptions { UseSharedSchemaWhenNoTenant = true });

        provider.GetSchemaName().Should().Be("tenant_acme_1");
    }

    [Fact]
    public void DbSchemaProvider_ShouldReturnTheTenantSchema_WhenATenantIsResolved()
    {
        var tenant = new TenantContext();
        tenant.SetTenant("acme-1");

        new DbSchemaProvider(tenant).GetSchemaName().Should().Be("tenant_acme_1");
    }
}
