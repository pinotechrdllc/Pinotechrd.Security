using System.Collections.Frozen;
using Microsoft.AspNetCore.Http;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Implements hierarchical security validation logic.
/// </summary>
public class SecurityEngine : ISecurityEngine
{
    private readonly ISecurityStore _securityStore;
    private readonly ISecurityDataProvider _dataProvider;
    private readonly TenantContext? _tenantContext;
    private readonly IHttpContextAccessor? _httpContextAccessor;
    private readonly string _claimType;

    /// <summary>
    /// Initializes the security engine.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The tenant the engine trusts is, for an HTTP request with an authenticated user, the user's tenant claim
    /// (read from authenticated identities only); it must also equal <see cref="TenantContext"/> when that is set.
    /// For an anonymous request, or outside HTTP (no <see cref="HttpContext"/>), it is <see cref="TenantContext"/>:
    /// background work must call <see cref="TenantContext.SetTenant"/> before using the engine.
    /// Every check denies, and every permission list is empty, when the tenant reported by
    /// <see cref="ISecurityDataProvider.GetCurrentTenantId"/> is not that trusted tenant, when the user carries
    /// no tenant claim or two different ones, or when no trusted tenant can be determined.
    /// </para>
    /// <para>
    /// <c>AddPinotechrdSecurity</c> registers all optional services. Constructed without
    /// <paramref name="tenantContext"/> and <paramref name="httpContextAccessor"/>, the engine trusts the data
    /// provider's tenant as is.
    /// </para>
    /// </remarks>
    public SecurityEngine(
        ISecurityStore securityStore,
        ISecurityDataProvider dataProvider,
        TenantContext? tenantContext = null,
        IHttpContextAccessor? httpContextAccessor = null,
        TenantResolutionOptions? tenantOptions = null)
    {
        _securityStore = securityStore;
        _dataProvider = dataProvider;
        _tenantContext = tenantContext;
        _httpContextAccessor = httpContextAccessor;
        _claimType = tenantOptions?.ClaimType ?? new TenantResolutionOptions().ClaimType;
    }

    private bool TenantMatchesRequest(string tenantId)
    {
        if (_tenantContext == null && _httpContextAccessor == null) return true;

        var trusted = TrustedTenant();
        return trusted != null && string.Equals(trusted, tenantId, StringComparison.Ordinal);
    }

    private string? TrustedTenant()
    {
        var status = TenantClaims.Read(_httpContextAccessor?.HttpContext?.User, _claimType, out var claimTenant);
        switch (status)
        {
            case TenantClaimStatus.Single:
                var resolved = _tenantContext?.TenantId;
                return resolved == null || string.Equals(resolved, claimTenant, StringComparison.Ordinal) ? claimTenant : null;
            case TenantClaimStatus.NotAuthenticated:
                return _tenantContext?.TenantId;
            default:
                return null;
        }
    }

    /// <summary>
    /// Evaluates if the current user can access a specific feature.
    /// Hierarchy: Subscription -> Module -> Permission.
    /// </summary>
    public async Task<bool> CanAccessAsync(string moduleCode, string permissionName, CancellationToken cancellationToken = default)
    {
        // 1. Resolve Identity and Context
        var userId = _dataProvider.GetCurrentUserId();
        var tenantId = _dataProvider.GetCurrentTenantId();

        // FAIL-FAST: No context, no access.
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(tenantId) || !TenantMatchesRequest(tenantId))
            return false;

        if (!SecurityCodes.TryNormalize(moduleCode, out moduleCode) || !SecurityCodes.TryNormalize(permissionName, out permissionName))
            return false;

        // 2. Validate Active Subscription (Business layer check)
        var hasSubscription = await _securityStore.IsSubscriptionActiveAsync(tenantId, cancellationToken);
        if (!hasSubscription) return false;

        // 3. Validate Module availability (Plan layer check)
        var isModuleActive = await _securityStore.IsModuleActiveAsync(tenantId, moduleCode, cancellationToken);
        if (!isModuleActive) return false;

        // 4. Role bundle, plus Allow, minus Deny. Only the full "MODULE.PERMISSION" code grants access:
        //    a bare permission name would grant that permission in every module.
        var permissions = await EffectivePermissionsAsync(userId, cancellationToken);
        return permissions.Contains(moduleCode + "." + permissionName);
    }

    /// <inheritdoc />
    public async Task<List<SecurityMenuItem>> GetAuthorizedMenuAsync(IEnumerable<SecurityMenuItem> fullMenu, CancellationToken cancellationToken = default)
    {
        // 1. Resolve Identity and Context
        var userId = _dataProvider.GetCurrentUserId();
        var tenantId = _dataProvider.GetCurrentTenantId();

        // FAIL-FAST: No context, no menu.
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(tenantId) || !TenantMatchesRequest(tenantId))
            return [];

        // 2. Validate Active Subscription (Business layer check - execute once for performance)
        var hasSubscription = await _securityStore.IsSubscriptionActiveAsync(tenantId, cancellationToken);
        if (!hasSubscription) return [];

        // 3. BATCH FETCHING (Senior Optimization)
        // Avoid N+1 queries by fetching all modules and permissions into high-performance sets
        var activeModules = (await _securityStore.GetActiveModuleCodesAsync(tenantId, cancellationToken))
            .ToFrozenSet(StringComparer.OrdinalIgnoreCase);

        var userPermissions = (await EffectivePermissionsAsync(userId, cancellationToken))
            .ToFrozenSet(StringComparer.OrdinalIgnoreCase);

        // 4. Recursive Filtering in Memory
        return FilterMenuItems(fullMenu, activeModules, userPermissions);
    }

    /// <summary>
    /// Recursively filters the menu items based on the provided authorized sets.
    /// </summary>
    private List<SecurityMenuItem> FilterMenuItems(
        IEnumerable<SecurityMenuItem> items, 
        FrozenSet<string> activeModules, 
        FrozenSet<string> userPermissions)
    {
        var authorizedItems = new List<SecurityMenuItem>();

        foreach (var item in items)
        {
            // HIERARCHY CHECK 1: Module
            // If the item belongs to a module, that module must be active in the tenant's plan.
            if (!string.IsNullOrEmpty(item.ModuleCode) 
                && !item.ModuleCode.Equals("CORE", StringComparison.OrdinalIgnoreCase)
                && !activeModules.Contains(item.ModuleCode))
                continue;

            // HIERARCHY CHECK 2: Permissions
            // If the item requires specific permissions, the user must have AT LEAST ONE.
            if (item.RequiredPermissions.Any() && !item.RequiredPermissions.Any(p => userPermissions.Contains(p)))
                continue;

            // RECURSION: Process children first
            var authorizedChildren = FilterMenuItems(item.Children, activeModules, userPermissions);

            // CLONE & ADD: Create a new instance for the output tree to keep original items immutable
            authorizedItems.Add(new SecurityMenuItem
            {
                TitleKey = item.TitleKey,
                Path = item.Path,
                Icon = item.Icon,
                Order = item.Order,
                ModuleCode = item.ModuleCode,
                RequiredPermissions = item.RequiredPermissions,
                Children = authorizedChildren
            });
        }

        // Maintain relative display order as defined in the metadata
        return authorizedItems.OrderBy(i => i.Order).ToList();
    }

    /// <inheritdoc />
    public async Task<IEnumerable<string>> GetPermissionsAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) 
            return [];

        var tenantId = _dataProvider.GetCurrentTenantId();
        if (!string.IsNullOrEmpty(tenantId) && !TenantMatchesRequest(tenantId))
        {
            return [];
        }

        var permissions = await EffectivePermissionsAsync(userId, cancellationToken);
        if (string.IsNullOrEmpty(tenantId))
        {
            return permissions;
        }

        var activeModules = (await _securityStore.GetActiveModuleCodesAsync(tenantId, cancellationToken))
            .ToFrozenSet(StringComparer.OrdinalIgnoreCase);

        return permissions.Where(code => IsModuleActive(code, activeModules)).ToList();
    }

    /// <inheritdoc />
    public Task<IEnumerable<string>> GetCurrentUserPermissionsAsync(CancellationToken cancellationToken = default)
    {
        // FAIL-FAST: no user or no tenant, no permissions (unlike GetPermissionsAsync, which then skips the module filter).
        var userId = _dataProvider.GetCurrentUserId();
        var tenantId = _dataProvider.GetCurrentTenantId();
        return string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(tenantId)
            ? Task.FromResult<IEnumerable<string>>([])
            : GetPermissionsAsync(userId, cancellationToken);
    }

    /// <summary>
    /// Role permissions from the provider, plus Allow overrides, minus Deny.
    /// Deny is applied last and wins.
    /// </summary>
    private async Task<HashSet<string>> EffectivePermissionsAsync(string userId, CancellationToken cancellationToken)
    {
        var granted = await _dataProvider.GetUserPermissionsAsync(userId, cancellationToken) ?? [];
        var set = new HashSet<string>(
            granted.Where(code => !string.IsNullOrWhiteSpace(code)),
            StringComparer.OrdinalIgnoreCase);

        var overrides = await _securityStore.GetUserOverridesAsync(userId, cancellationToken) ?? [];
        foreach (var item in overrides)
        {
            if (string.IsNullOrWhiteSpace(item.Code) || item.Access != PermissionAccessType.Allow)
            {
                continue;
            }

            set.Add(item.Code);
        }

        foreach (var item in overrides)
        {
            if (string.IsNullOrWhiteSpace(item.Code) || item.Access != PermissionAccessType.Deny)
            {
                continue;
            }

            set.Remove(item.Code);
        }

        return set;
    }

    private static bool IsModuleActive(string code, FrozenSet<string> activeModules)
    {
        var separator = code.IndexOf('.');
        if (separator <= 0)
        {
            return true;
        }

        var moduleCode = code[..separator];
        return moduleCode.Equals("CORE", StringComparison.OrdinalIgnoreCase)
            || activeModules.Contains(moduleCode);
    }
}
