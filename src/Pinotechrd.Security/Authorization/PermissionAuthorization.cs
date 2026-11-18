using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Interfaces;
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
    public PermissionRequirement(string fullName)
    {
        FullName = fullName;
        var parts = fullName.Split('.', 2);
        if (parts.Length == 2)
        {
            ModuleCode = parts[0];
            Permission = parts[1];
        }
        else
        {
            ModuleCode = "Global"; // Default or fallback
            Permission = fullName;
        }
    }
}

/// <summary>
/// Handler for validating permission requirements using the SecurityEngine.
/// </summary>
public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    private readonly ISecurityEngine _securityEngine;

    /// <summary>
    /// Initializes the authorization handler.
    /// </summary>
    public PermissionAuthorizationHandler(ISecurityEngine securityEngine)
    {
        _securityEngine = securityEngine;
    }

    /// <summary>
    /// Validates the permission requirement against the security engine.
    /// </summary>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        // The engine handles: Subscription Check -> Module Check -> User/Role Permission Check
        if (await _securityEngine.CanAccessAsync(requirement.ModuleCode, requirement.Permission))
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
