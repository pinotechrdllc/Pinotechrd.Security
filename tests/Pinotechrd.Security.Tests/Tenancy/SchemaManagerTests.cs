using FluentAssertions;
using NSubstitute;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Tenancy;

/// <summary>The schema name rule. The name is placed inside SQL, so it is checked before any statement is built.</summary>
public class SchemaManagerTests
{
    private readonly SchemaManager _manager = new(Substitute.For<ISecurityDbContext>());

    [Theory]
    [InlineData("Tenant_A")]
    [InlineData("tenant-a")]
    [InlineData("1tenant")]
    [InlineData("tenant a")]
    [InlineData("a\"; DROP SCHEMA x; --")]
    public async Task CreateSchemaAsync_ShouldThrowArgumentException_WhenTheNameBreaksTheRule(string name)
    {
        var act = () => _manager.CreateSchemaAsync(name);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task CreateSchemaAsync_ShouldThrowArgumentException_WhenTheNameHasSixtyFourCharacters()
    {
        var act = () => _manager.CreateSchemaAsync(new string('a', 64));

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task CreateSchemaAsync_ShouldThrowArgumentException_WhenTheNameHasATrailingNewline()
    {
        var act = () => _manager.CreateSchemaAsync("tenant_a\n");

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(63)]
    public async Task CreateSchemaAsync_ShouldPassValidation_WhenTheNameIsLowerCaseAndAtMostSixtyThreeCharacters(int length)
    {
        // The substitute is not an EF context, so a name that passes the rule reaches that check instead.
        var act = () => _manager.CreateSchemaAsync(new string('a', length));

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task CreateTenantSchemaAsync_ShouldThrowArgumentException_WhenTheTenantIdIsNotWellFormed()
    {
        var act = () => _manager.CreateTenantSchemaAsync("Tenant_A");

        await act.Should().ThrowAsync<ArgumentException>();
    }
}
