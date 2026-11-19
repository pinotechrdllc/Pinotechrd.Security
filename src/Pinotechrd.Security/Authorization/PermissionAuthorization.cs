using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using System.Security.Claims;

namespace Pinotechrd.Security.Authorization;

/// <summary>
/// Requirement for permission-based authorization.
/// Supports "Module.Permission" format.
/// </summary>
public class PermissionRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Full permission name (for example, "Users.View").
    /// </summary>
    public string FullName { get; }

    /// <summary>
    /// Module portion of the permission name.
    /// </summary>
    public string ModuleCode { get; }

    /// <summary>
    /// Permission portion within the module.
    /// </summary>
    public string Permission { get; }

    /// <summary>
    /// Initializes a permission requirement from a policy string.
    /// </summary>
    /// <remarks>
    /// <see cref="ModuleCode"/> and <see cref="Permission"/> are normalised (trimmed, upper case), as stored codes are,
    /// so <c>Sales.View</c> and <c>SALES.VIEW</c> are the same requirement. A name without a dot is the permission
    /// of module <c>GLOBAL</c>, and only the code <c>GLOBAL.NAME</c> grants it.
    /// </remarks>
    /// <exception cref="ArgumentException">A part is empty or has characters outside <c>A-Z a-z 0-9 _ . -</c>.</exception>
    public PermissionRequirement(string fullName)
    {
        FullName = fullName;
        var parts = fullName.Split('.', 2);
        if (parts.Length == 2)
        {
            ModuleCode = SecurityCodes.Normalize(parts[0]);
            Permission = SecurityCodes.Normalize(parts[1]);
        }
        else
        {
            ModuleCode = "GLOBAL"; // Default or fallback
            Permission = SecurityCodes.Normalize(fullName);
        }
    }
}

/// <summary>
/// Handler for validating permission requirements using the SecurityEngine.
/// </summary>
/// <remarks>
/// Before asking the engine, the handler requires an authenticated principal whose tenant claim
/// (<see cref="TenantResolutionOptions.ClaimType"/>) equals the tenant resolved for the request
/// (<see cref="TenantContext"/>). A missing claim, two authenticated identities with different tenants, an
/// unresolved tenant or a difference fails the requirement. Claims of unauthenticated identities are ignored.
/// This catches a principal authenticated by a scheme the tenant middleware did not see.
/// </remarks>
public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    private readonly ISecurityEngine _securityEngine;
    private readonly TenantContext? _tenantContext;
    private readonly string _claimType;

    /// <summary>
    /// Initializes the authorization handler.
    /// </summary>
    /// <remarks>
    /// Without <paramref name="tenantContext"/> every requirement fails, because the tenant cannot be checked.
    /// <c>AddPinotechrdSecurity</c> registers both optional services.
    /// </remarks>
    public PermissionAuthorizationHandler(
        ISecurityEngine securityEngine,
        TenantContext? tenantContext = null,
        TenantResolutionOptions? tenantOptions = null)
    {
        _securityEngine = securityEngine;
        _tenantContext = tenantContext;
        _claimType = tenantOptions?.ClaimType ?? new TenantResolutionOptions().ClaimType;
    }

    /// <summary>
    /// Validates the permission requirement against the security engine.
    /// </summary>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var resolvedTenant = _tenantContext?.TenantId;
        var status = TenantClaims.Read(context.User, _claimType, out var claimTenant);
        if (string.IsNullOrEmpty(resolvedTenant)
            || status != TenantClaimStatus.Single
            || !string.Equals(resolvedTenant, claimTenant, StringComparison.Ordinal))
        {
            context.Fail(new AuthorizationFailureReason(this, "The tenant of the principal does not match the tenant of the request."));
            return;
        }

        // The engine handles: Subscription Check -> Module Check -> User/Role Permission Check
        var cancellationToken = (context.Resource as HttpContext)?.RequestAborted ?? CancellationToken.None;
        if (await _securityEngine.CanAccessAsync(requirement.ModuleCode, requirement.Permission, cancellationToken))
        {
            context.Succeed(requirement);
        }
    }
}

/// <summary>
/// Custom policy provider that dynamically creates policies for permission strings.
/// Format: "Module.Permission"
/// </summary>
public class PermissionPolicyProvider : DefaultAuthorizationPolicyProvider
{
    /// <summary>
    /// Initializes the dynamic permission policy provider.
    /// </summary>
    public PermissionPolicyProvider(IOptions<AuthorizationOptions> options) : base(options)
    {
    }

    /// <summary>
    /// Resolves or dynamically creates a policy for the given permission name.
    /// </summary>
    public override async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        var policy = await base.GetPolicyAsync(policyName);

        if (policy == null)
        {
            // If the policy is not predefined, we treat it as a permission requirement
            policy = new AuthorizationPolicyBuilder()
                .AddRequirements(new PermissionRequirement(policyName))
                .Build();
        }

        return policy;
    }
}
