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

        if (!SecurityCodes.TryNormalizeModule(moduleCode, out moduleCode) || !SecurityCodes.TryNormalize(permissionName, out permissionName))
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
        var activeModules = NormalizedModuleSet(await _securityStore.GetActiveModuleCodesAsync(tenantId, cancellationToken));

        var userPermissions = (await EffectivePermissionsAsync(userId, cancellationToken))
            .ToFrozenSet(StringComparer.Ordinal);

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
            // If the item belongs to a module, that module must be active in the tenant's plan. No module code is
            // exempt (CORE included), so the menu agrees with CanAccessAsync.
            if (!string.IsNullOrEmpty(item.ModuleCode) && !IsActiveModuleCode(item.ModuleCode, activeModules))
                continue;

            // HIERARCHY CHECK 2: Permissions
            // If the item requires specific permissions, the user must have AT LEAST ONE whose module is active in the
            // plan, as CanAccessAsync requires, whether or not the item names a module. Required codes are normalised
            // like the user's codes; one that cannot be normalised is never held.
            if (item.RequiredPermissions.Any()
                && !item.RequiredPermissions.Any(p => TryNormalizePermission(p, out var required)
                    && userPermissions.Contains(required)
                    && IsModuleActive(required, activeModules)))
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

        // No tenant, no permissions: without one there is no plan to check the modules against, and CanAccessAsync,
        // the menu and GetCurrentUserPermissionsAsync grant nothing either. Nor for a tenant other than the request's.
        var tenantId = _dataProvider.GetCurrentTenantId();
        if (string.IsNullOrEmpty(tenantId) || !TenantMatchesRequest(tenantId))
        {
            return [];
        }

        var permissions = await EffectivePermissionsAsync(userId, cancellationToken);
        var activeModules = NormalizedModuleSet(await _securityStore.GetActiveModuleCodesAsync(tenantId, cancellationToken));

        return permissions.Where(code => IsModuleActive(code, activeModules)).ToList();
    }

    /// <inheritdoc />
    public Task<IEnumerable<string>> GetCurrentUserPermissionsAsync(CancellationToken cancellationToken = default)
    {
        // FAIL-FAST: no user or no tenant, no permissions.
        var userId = _dataProvider.GetCurrentUserId();
        var tenantId = _dataProvider.GetCurrentTenantId();
        return string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(tenantId)
            ? Task.FromResult<IEnumerable<string>>([])
            : GetPermissionsAsync(userId, cancellationToken);
    }

    /// <summary>
    /// Role permissions from the provider, plus Allow overrides, minus Deny. Deny is applied last and wins.
    /// </summary>
    /// <remarks>
    /// Every code is normalised (trimmed, upper case) as codes written through the API are, so a role code and an
    /// override code that differ only in case or surrounding spaces are the same permission, and a Deny always removes
    /// the grant it names. A code that cannot be normalised (empty, or outside the code alphabet) grants nothing and is
    /// left out; a malformed Deny therefore cannot be honoured either, which is why the API refuses to write one.
    /// </remarks>
    private async Task<HashSet<string>> EffectivePermissionsAsync(string userId, CancellationToken cancellationToken)
    {
        var granted = await _dataProvider.GetUserPermissionsAsync(userId, cancellationToken) ?? [];
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var code in granted)
        {
            if (TryNormalizePermission(code, out var normalized)) set.Add(normalized);
        }

        var overrides = await _securityStore.GetUserOverridesAsync(userId, cancellationToken) ?? [];
        foreach (var item in overrides)
        {
            if (item.Access == PermissionAccessType.Allow && TryNormalizePermission(item.Code, out var normalized))
            {
                set.Add(normalized);
            }
        }

        foreach (var item in overrides)
        {
            if (item.Access == PermissionAccessType.Deny && TryNormalizePermission(item.Code, out var normalized))
            {
                set.Remove(normalized);
            }
        }

        return set;
    }

    private static bool TryNormalizePermission(string? code, out string normalized) =>
        SecurityCodes.TryNormalizePermission(code, out normalized);

    /// <summary>Whether the module of a normalised permission code is active; a code without a module never is.</summary>
    private static bool IsModuleActive(string code, FrozenSet<string> activeModules)
    {
        var separator = code.IndexOf('.');
        if (separator <= 0)
        {
            return false;
        }

        // No module code is exempt (CORE included): a permission is listed, and written to tokens, only when its module is
        // in the tenant's plan, as CanAccessAsync requires.
        return IsActiveModuleCode(code[..separator], activeModules);
    }

    /// <summary>
    /// The tenant's active module codes, normalised as <see cref="CanAccessAsync"/> normalises the code it checks.
    /// A stored code outside the code alphabet is left out.
    /// </summary>
    private static FrozenSet<string> NormalizedModuleSet(IEnumerable<string> codes) =>
        codes.Select(code => SecurityCodes.TryNormalizeModule(code, out var normalized) ? normalized : null)
            .OfType<string>()
            .ToFrozenSet(StringComparer.Ordinal);

    /// <summary>Whether a module code, normalised the same way, is active; an invalid code never is.</summary>
    private static bool IsActiveModuleCode(string moduleCode, FrozenSet<string> activeModules) =>
        SecurityCodes.TryNormalizeModule(moduleCode, out var normalized) && activeModules.Contains(normalized);
}
