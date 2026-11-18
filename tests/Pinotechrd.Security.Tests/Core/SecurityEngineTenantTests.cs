using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>The engine refuses to answer for a tenant other than the one the request was resolved for, and normalizes codes.</summary>
public class SecurityEngineTenantTests
{
    private readonly ISecurityDataProvider _provider = Substitute.For<ISecurityDataProvider>();
    private readonly ISecurityStore _store = Substitute.For<ISecurityStore>();

    private SecurityEngine Engine(string? requestTenant, bool withContext = true)
    {
        TenantContext? context = null;
        if (withContext)
        {
            context = new TenantContext();
            if (requestTenant != null) context.SetTenant(requestTenant);
        }

        return new SecurityEngine(_store, _provider, context);
    }

    private void Allow(string tenant)
    {
        _provider.GetCurrentUserId().Returns("user-1");
        _provider.GetCurrentTenantId().Returns(tenant);
        _store.IsSubscriptionActiveAsync(tenant).Returns(true);
        _store.IsModuleActiveAsync(tenant, Arg.Any<string>()).Returns(true);
        _store.GetActiveModuleCodesAsync(tenant).Returns(["SALES"]);
        _provider.GetUserPermissionsAsync("user-1").Returns(new List<string> { "SALES.VIEW" });
    }

    [Fact]
    public async Task CanAccessAsync_ShouldBeFalseWithoutTouchingTheStore_WhenTheTenantContextDiffersFromTheDataProviderTenant()
    {
        Allow("tenant-a");

        var result = await Engine("tenant-b").CanAccessAsync("SALES", "VIEW");

        result.Should().BeFalse();
        await _store.DidNotReceiveWithAnyArgs().IsSubscriptionActiveAsync(default!);
    }

    [Fact]
    public async Task CanAccessAsync_ShouldBeFalse_WhenTheTenantDiffersOnlyByCase()
    {
        Allow("TENANT-A");

        (await Engine("tenant-a").CanAccessAsync("SALES", "VIEW")).Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldBeFalse_WhenTheContextHasNoTenant()
    {
        Allow("tenant-a");

        (await Engine(requestTenant: null).CanAccessAsync("SALES", "VIEW")).Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldBeTrue_WhenTheTenantsMatch()
    {
        Allow("tenant-a");

        (await Engine("tenant-a").CanAccessAsync("SALES", "VIEW")).Should().BeTrue();
    }

    [Fact]
    public async Task GetAuthorizedMenuAsync_ShouldBeEmpty_WhenTheTenantContextDiffersFromTheDataProviderTenant()
    {
        Allow("tenant-a");
        var menu = new[] { new SecurityMenuItem { TitleKey = "sales", ModuleCode = "SALES", Order = 1 } };

        var result = await Engine("tenant-b").GetAuthorizedMenuAsync(menu);

        result.Should().BeEmpty();
        await _store.DidNotReceiveWithAnyArgs().IsSubscriptionActiveAsync(default!);
    }

    [Fact]
    public async Task GetAuthorizedMenuAsync_ShouldListTheItem_WhenTheTenantsMatch()
    {
        Allow("tenant-a");
        var menu = new[] { new SecurityMenuItem { TitleKey = "sales", ModuleCode = "SALES", Order = 1 } };

        var result = await Engine("tenant-a").GetAuthorizedMenuAsync(menu);

        result.Should().ContainSingle();
    }

    [Fact]
    public async Task GetPermissionsAsync_ShouldBeEmpty_WhenTheTenantContextDiffersFromTheDataProviderTenant()
    {
        Allow("tenant-a");

        var result = await Engine("tenant-b").GetPermissionsAsync("user-1");

        result.Should().BeEmpty();
        await _provider.DidNotReceiveWithAnyArgs().GetUserPermissionsAsync(default!);
    }

    [Fact]
    public async Task GetPermissionsAsync_ShouldReturnThePermissions_WhenTheTenantsMatch()
    {
        Allow("tenant-a");

        var result = await Engine("tenant-a").GetPermissionsAsync("user-1");

        result.Should().Contain("SALES.VIEW");
    }

    [Fact]
    public async Task CanAccessAsync_ShouldTreatCodesCaseInsensitivelyAndTrimThem()
    {
        Allow("tenant-a");
        var engine = Engine("tenant-a");

        var mixed = await engine.CanAccessAsync("Sales", "View");
        var padded = await engine.CanAccessAsync(" sales ", " view ");
        var upper = await engine.CanAccessAsync("SALES", "VIEW");

        mixed.Should().BeTrue();
        padded.Should().Be(upper);
        await _store.Received(3).IsModuleActiveAsync("tenant-a", "SALES");
    }

    [Fact]
    public async Task CanAccessAsync_ShouldBeFalse_WhenThePermissionIsNotGranted_EvenIfTheCaseDiffers()
    {
        Allow("tenant-a");

        (await Engine("tenant-a").CanAccessAsync("sales", "delete")).Should().BeFalse();
    }

    // ---- The data provider's tenant against the authenticated user's claim -----------------------

    private SecurityEngine EngineWithHttp(string? requestTenant, ClaimsPrincipal? user, bool httpContext = true)
    {
        var context = new TenantContext();
        if (requestTenant != null) context.SetTenant(requestTenant);
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext ? new DefaultHttpContext { User = user ?? new ClaimsPrincipal(new ClaimsIdentity()) } : null);
        return new SecurityEngine(_store, _provider, context, accessor);
    }

    private static ClaimsPrincipal UserOf(params string[] tenants) =>
        new(tenants.Select(t => new ClaimsIdentity([new Claim("tenant_id", t)], "Bearer")));

    [Fact]
    public async Task Engine_ShouldDeny_WhenTheDataProviderTenantDiffersFromTheAuthenticatedUsersClaim()
    {
        Allow("tenant-b");
        var engine = EngineWithHttp("tenant-b", UserOf("tenant-a"));

        (await engine.CanAccessAsync("SALES", "VIEW")).Should().BeFalse();
        (await engine.GetPermissionsAsync("user-1")).Should().BeEmpty();
        (await engine.GetAuthorizedMenuAsync([new SecurityMenuItem { TitleKey = "sales", ModuleCode = "SALES" }])).Should().BeEmpty();
    }

    [Fact]
    public async Task Engine_ShouldDeny_WhenTheClaimDiffersFromTheTenantContext_EvenIfTheProviderAgreesWithTheContext()
    {
        Allow("tenant-b");
        var engine = EngineWithHttp("tenant-b", UserOf("tenant-a"));

        (await engine.CanAccessAsync("SALES", "VIEW")).Should().BeFalse();
        await _store.DidNotReceiveWithAnyArgs().IsSubscriptionActiveAsync(default!);
    }

    [Fact]
    public async Task Engine_ShouldDeny_WhenTheClaimAndTheContextAgreeButTheProviderNamesAnotherTenant()
    {
        Allow("tenant-b");
        var engine = EngineWithHttp("tenant-a", UserOf("tenant-a"));

        (await engine.CanAccessAsync("SALES", "VIEW")).Should().BeFalse();
        (await engine.GetPermissionsAsync("user-1")).Should().BeEmpty();
        (await engine.GetAuthorizedMenuAsync([new SecurityMenuItem { TitleKey = "sales", ModuleCode = "SALES" }])).Should().BeEmpty();
    }

    [Fact]
    public async Task Engine_ShouldAllow_WhenClaimContextAndProviderAllAgree()
    {
        Allow("tenant-a");
        var engine = EngineWithHttp("tenant-a", UserOf("tenant-a"));

        (await engine.CanAccessAsync("SALES", "VIEW")).Should().BeTrue();
        (await engine.GetPermissionsAsync("user-1")).Should().Contain("SALES.VIEW");
    }

    [Fact]
    public async Task Engine_ShouldDeny_WhenTwoAuthenticatedIdentitiesNameDifferentTenants()
    {
        Allow("tenant-a");
        var engine = EngineWithHttp("tenant-a", UserOf("tenant-a", "tenant-b"));

        (await engine.CanAccessAsync("SALES", "VIEW")).Should().BeFalse();
    }

    [Fact]
    public async Task Engine_ShouldIgnoreAClaimOnAnUnauthenticatedIdentity_AndUseTheTenantContext()
    {
        Allow("tenant-a");
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant_id", "tenant-evil")]));
        var engine = EngineWithHttp("tenant-a", user);

        (await engine.CanAccessAsync("SALES", "VIEW")).Should().BeTrue();
    }

    [Fact]
    public async Task Engine_ShouldUseTheTenantContext_WhenThereIsNoHttpContext()
    {
        Allow("tenant-a");

        (await EngineWithHttp("tenant-a", null, httpContext: false).CanAccessAsync("SALES", "VIEW")).Should().BeTrue();
        (await EngineWithHttp("tenant-b", null, httpContext: false).CanAccessAsync("SALES", "VIEW")).Should().BeFalse();
        (await EngineWithHttp("tenant-b", null, httpContext: false).GetPermissionsAsync("user-1")).Should().BeEmpty();
    }

    [Fact]
    public async Task Engine_ShouldDeny_WhenThereIsNoHttpContextAndNoTenantContextToTrust()
    {
        Allow("tenant-a");
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns((HttpContext?)null);
        var engine = new SecurityEngine(_store, _provider, null, accessor);

        (await engine.CanAccessAsync("SALES", "VIEW")).Should().BeFalse();
    }

    // ---- Codes -------------------------------------------------------------------------------

    [Fact]
    public async Task CanAccessAsync_ShouldNotGrant_WhenTheUserHoldsOnlyTheBarePermissionName()
    {
        Allow("tenant-a");
        _provider.GetUserPermissionsAsync("user-1").Returns(new List<string> { "VIEW" });

        (await Engine("tenant-a").CanAccessAsync("SALES", "VIEW")).Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldGrantADotLessRequirement_OnlyThroughTheGlobalModule()
    {
        Allow("tenant-a");
        _provider.GetUserPermissionsAsync("user-1").Returns(new List<string> { "GLOBAL.REPORTS" });
        var requirement = new Pinotechrd.Security.Authorization.PermissionRequirement("reports");

        (await Engine("tenant-a").CanAccessAsync(requirement.ModuleCode, requirement.Permission)).Should().BeTrue();
        _provider.GetUserPermissionsAsync("user-1").Returns(new List<string> { "REPORTS" });
        (await Engine("tenant-a").CanAccessAsync(requirement.ModuleCode, requirement.Permission)).Should().BeFalse();
    }

    [Theory]
    [InlineData("SAL ES", "VIEW")]
    [InlineData("SALES", "VI EW")]
    [InlineData("SALES", "")]
    [InlineData("", "VIEW")]
    [InlineData("SAL\u017Fes", "VIEW")]
    [InlineData("SALES", "VIEW;DROP")]
    [InlineData("SALES", "VI/EW")]
    public async Task CanAccessAsync_ShouldBeFalse_ForAnInvalidCode(string module, string permission)
    {
        Allow("tenant-a");
        _store.IsModuleActiveAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);

        (await Engine("tenant-a").CanAccessAsync(module, permission)).Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldAcceptACodeOf100Characters_AndRejectOneOf101()
    {
        var module100 = new string('M', 100);
        var module101 = new string('M', 101);
        _provider.GetCurrentUserId().Returns("user-1");
        _provider.GetCurrentTenantId().Returns("tenant-a");
        _store.IsSubscriptionActiveAsync("tenant-a").Returns(true);
        _store.IsModuleActiveAsync("tenant-a", Arg.Any<string>()).Returns(true);
        _provider.GetUserPermissionsAsync("user-1").Returns(new List<string> { module100 + ".VIEW", module101 + ".VIEW" });
        var engine = Engine("tenant-a");

        (await engine.CanAccessAsync(module100, "VIEW")).Should().BeTrue();
        (await engine.CanAccessAsync(module101, "VIEW")).Should().BeFalse();
    }
}
