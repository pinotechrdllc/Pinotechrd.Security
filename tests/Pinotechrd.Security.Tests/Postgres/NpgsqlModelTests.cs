using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// The model rules of the two schema modes, built with the Npgsql provider. Building a model needs no server, so these tests
/// run without Docker.
/// </summary>
public class NpgsqlModelTests
{
    private const string Dummy = "Host=localhost;Database=none;Username=u;Password=p";

    private static SecDb Context(string? tenant, bool usePinotechrd = true, TenantSchemaMode mode = TenantSchemaMode.SchemaPerTenantInModel, Action<DbContextOptionsBuilder<SecDb>>? configure = null)
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseNpgsql(Dummy);
        if (usePinotechrd) builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = mode);
        configure?.Invoke(builder);
        return new SecDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant(tenant)));
    }

    [Fact]
    public void Model_ShouldRefuseToBuild_WithoutUsePinotechrdSecurity()
    {
        using var db = Context("a", usePinotechrd: false);

        var act = () => db.Model;

        act.Should().Throw<InvalidOperationException>().WithMessage("*UsePinotechrdSecurity*");
    }

    [Fact]
    public void UseModel_ShouldBeRefused_InSchemaPerTenantMode()
    {
        using var source = Context("a", mode: TenantSchemaMode.SearchPath);
        var model = source.Model;

        var act = () => Context("a", configure: b => b.UseModel(model));

        act.Should().Throw<InvalidOperationException>().WithMessage("*UseModel*");
    }

    [Fact]
    public void UseModel_ShouldBeAccepted_InSearchPathMode()
    {
        using var source = Context("a", mode: TenantSchemaMode.SearchPath);
        var model = source.Model;

        var act = () => Context("b", mode: TenantSchemaMode.SearchPath, configure: b => b.UseModel(model));

        act.Should().NotThrow();
    }

    [Fact]
    public void Model_ShouldDifferPerTenant_AndBeReusedForTheSameTenantInAnotherScope()
    {
        using var a1 = Context("a");
        using var b = Context("b");
        using var a2 = Context("a");

        a1.Model.Should().NotBeSameAs(b.Model);
        a2.Model.Should().BeSameAs(a1.Model, "a third scope for tenant a reuses tenant a's cached model");
        a1.Model.FindEntityType(typeof(HostUser))!.GetSchema().Should().Be("tenant_a");
        b.Model.FindEntityType(typeof(HostUser))!.GetSchema().Should().Be("tenant_b");
        a1.Model.FindEntityType(typeof(SubscriptionPlan))!.GetSchema().Should().Be("public", "the catalog schema is constant");
        b.Model.FindEntityType(typeof(SubscriptionPlan))!.GetSchema().Should().Be("public");
    }

    [Fact]
    public void Model_ShouldBeOneInstanceForEveryTenant_InSearchPathMode_WithNoTenantSchema()
    {
        using var a = Context("a", mode: TenantSchemaMode.SearchPath);
        using var b = Context("b", mode: TenantSchemaMode.SearchPath);

        a.Model.Should().BeSameAs(b.Model);
        a.Model.FindEntityType(typeof(HostUser))!.GetSchema().Should().BeNull();
        a.Model.FindEntityType(typeof(SubscriptionPlan))!.GetSchema().Should().Be("public");
    }

    [Fact]
    public void Model_ShouldNotShareACacheEntryBetweenTheTwoModes()
    {
        using var inModel = Context("a");
        using var searchPath = Context("a", mode: TenantSchemaMode.SearchPath);

        inModel.Model.Should().NotBeSameAs(searchPath.Model);
    }

    [Fact]
    public void Context_ShouldRefuseToStart_WhenTheSharedSchemaFallbackIsOnInSearchPathMode()
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseNpgsql(Dummy);
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);

        var act = () => new SecDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant(null), new TenantResolutionOptions { UseSharedSchemaWhenNoTenant = true }));

        act.Should().Throw<InvalidOperationException>().WithMessage("*UseSharedSchemaWhenNoTenant*");
    }
}
