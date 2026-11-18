using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using NSubstitute;
using Pinotechrd.Security.Authorization;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Authorization;

public class PermissionAuthorizationHandlerTests
{
    private readonly ISecurityEngine _engine = Substitute.For<ISecurityEngine>();

    private static TenantContext ContextFor(string? tenant)
    {
        var context = new TenantContext();
        if (tenant != null) context.SetTenant(tenant);
        return context;
    }

    private PermissionAuthorizationHandler Handler(TenantContext? tenant, TenantResolutionOptions? options = null) =>
        new(_engine, tenant, options);

    private static ClaimsPrincipal Principal(string? tenantClaim, bool authenticated = true)
    {
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, "user-1") };
        if (tenantClaim != null) claims.Add(new Claim("tenant_id", tenantClaim));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticated ? "Bearer" : null));
    }

    private static AuthorizationHandlerContext Context(PermissionRequirement requirement, ClaimsPrincipal user) =>
        new([requirement], user, null);

    [Fact]
    public async Task HandleRequirementAsync_ShouldSucceed_WhenTheClaimMatchesTheTenantContextAndTheEngineReturnsTrue()
    {
        var requirement = new PermissionRequirement("MODULE.READ");
        _engine.CanAccessAsync("MODULE", "READ").Returns(true);
        var context = Context(requirement, Principal("tenant-a"));

        await Handler(ContextFor("tenant-a")).HandleAsync(context);

        context.HasSucceeded.Should().BeTrue();
        await _engine.Received(1).CanAccessAsync("MODULE", "READ");
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldNotSucceedAndNotFail_WhenTheTenantMatchesButTheEngineReturnsFalse()
    {
        var requirement = new PermissionRequirement("MOD.PERM");
        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(false);
        var context = Context(requirement, Principal("tenant-a"));

        await Handler(ContextFor("tenant-a")).HandleAsync(context);

        context.HasSucceeded.Should().BeFalse();
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldFailWithoutAskingTheEngine_WhenTheClaimIsMissing()
    {
        var context = Context(new PermissionRequirement("MOD.PERM"), Principal(tenantClaim: null));
        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);

        await Handler(ContextFor("tenant-a")).HandleAsync(context);

        context.HasSucceeded.Should().BeFalse();
        context.HasFailed.Should().BeTrue();
        await _engine.DidNotReceiveWithAnyArgs().CanAccessAsync(default!, default!);
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldFailWithoutAskingTheEngine_WhenTheTenantContextIsUnset()
    {
        var context = Context(new PermissionRequirement("MOD.PERM"), Principal("tenant-a"));
        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);

        await Handler(ContextFor(null)).HandleAsync(context);

        context.HasSucceeded.Should().BeFalse();
        context.HasFailed.Should().BeTrue();
        await _engine.DidNotReceiveWithAnyArgs().CanAccessAsync(default!, default!);
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldFail_WhenThereIsNoTenantContextAtAll()
    {
        var context = Context(new PermissionRequirement("MOD.PERM"), Principal("tenant-a"));
        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);

        await Handler(tenant: null).HandleAsync(context);

        context.HasSucceeded.Should().BeFalse();
        await _engine.DidNotReceiveWithAnyArgs().CanAccessAsync(default!, default!);
    }

    [Theory]
    [InlineData("tenant-b")]
    [InlineData("TENANT-A")]
    [InlineData("tenant-a ")]
    public async Task HandleRequirementAsync_ShouldFailWithoutAskingTheEngine_WhenTheClaimDiffersFromTheTenantContext(string claim)
    {
        var context = Context(new PermissionRequirement("MOD.PERM"), Principal(claim));
        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);

        await Handler(ContextFor("tenant-a")).HandleAsync(context);

        context.HasSucceeded.Should().BeFalse();
        context.HasFailed.Should().BeTrue();
        await _engine.DidNotReceiveWithAnyArgs().CanAccessAsync(default!, default!);
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldFail_WhenTheClaimSitsOnlyOnAnUnauthenticatedIdentity()
    {
        var authenticatedWithoutClaim = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "user-1")], "Bearer");
        var unauthenticatedWithClaim = new ClaimsIdentity([new Claim("tenant_id", "tenant-a")]);
        var user = new ClaimsPrincipal([authenticatedWithoutClaim, unauthenticatedWithClaim]);
        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);
        var context = Context(new PermissionRequirement("MOD.PERM"), user);

        await Handler(ContextFor("tenant-a")).HandleAsync(context);

        context.HasSucceeded.Should().BeFalse();
        await _engine.DidNotReceiveWithAnyArgs().CanAccessAsync(default!, default!);
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldFail_WhenThePrincipalIsNotAuthenticatedAtAll()
    {
        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);
        var context = Context(new PermissionRequirement("MOD.PERM"), Principal("tenant-a", authenticated: false));

        await Handler(ContextFor("tenant-a")).HandleAsync(context);

        context.HasSucceeded.Should().BeFalse();
        await _engine.DidNotReceiveWithAnyArgs().CanAccessAsync(default!, default!);
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldUseTheClaimOfTheAuthenticatedIdentity_WhenAnotherIdentityCarriesADifferentOne()
    {
        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);
        var unauthenticated = new ClaimsIdentity([new Claim("tenant_id", "tenant-evil")]);
        var authenticated = new ClaimsIdentity([new Claim("tenant_id", "tenant-a")], "Bearer");
        var context = Context(new PermissionRequirement("MOD.PERM"), new ClaimsPrincipal([unauthenticated, authenticated]));

        await Handler(ContextFor("tenant-a")).HandleAsync(context);

        context.HasSucceeded.Should().BeTrue();
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldReadTheConfiguredClaimType()
    {
        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("org", "tenant-a")], "Bearer"));
        var context = Context(new PermissionRequirement("MOD.PERM"), user);

        await Handler(ContextFor("tenant-a"), new TenantResolutionOptions { ClaimType = "org" }).HandleAsync(context);

        context.HasSucceeded.Should().BeTrue();
    }

    // ---- Codes are normalized ---------------------------------------------------------------

    [Fact]
    public void PermissionRequirement_ShouldNormalizeTheModuleAndPermissionToUpperCase()
    {
        var requirement = new PermissionRequirement("sales.view");

        requirement.ModuleCode.Should().Be("SALES");
        requirement.Permission.Should().Be("VIEW");
        requirement.FullName.Should().Be("sales.view");
    }

    [Fact]
    public void PermissionRequirement_ShouldUseTheGlobalModule_WhenThereIsNoDot()
    {
        var requirement = new PermissionRequirement("view");

        requirement.ModuleCode.Should().Be("GLOBAL");
        requirement.Permission.Should().Be("VIEW");
    }

    [Fact]
    public void PermissionRequirement_ShouldKeepTheRestAfterTheFirstDotInThePermission()
    {
        var requirement = new PermissionRequirement("sales.orders.view");

        requirement.ModuleCode.Should().Be("SALES");
        requirement.Permission.Should().Be("ORDERS.VIEW");
    }

    [Fact]
    public void PermissionRequirement_ShouldTrimWhitespace()
    {
        var requirement = new PermissionRequirement(" sales . view ");

        requirement.ModuleCode.Should().Be("SALES");
        requirement.Permission.Should().Be("VIEW");
    }

    [Theory]
    [InlineData("Sa\u017Fes.View")]
    [InlineData("sales.Vi\u017Fw")]
    [InlineData("sa les.view")]
    [InlineData("sales.vi/ew")]
    [InlineData("")]
    [InlineData("sales.")]
    [InlineData(".view")]
    public void PermissionRequirement_ShouldThrowArgumentException_ForAnInvalidCode(string policy)
    {
        var act = () => new PermissionRequirement(policy);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void PermissionRequirement_ShouldAccept100Characters_AndRejectMore()
    {
        var ok = () => new PermissionRequirement(new string('m', 100) + "." + new string('p', 100));
        var tooLong = () => new PermissionRequirement(new string('m', 101) + ".view");

        ok.Should().NotThrow();
        tooLong.Should().Throw<ArgumentException>();
    }
}
