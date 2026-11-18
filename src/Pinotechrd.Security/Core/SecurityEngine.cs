using System.Collections.Frozen;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Implements hierarchical security validation logic.
/// </summary>
public class SecurityEngine : ISecurityEngine
{
    private readonly ISecurityStore _securityStore;
    private readonly ISecurityDataProvider _dataProvider;

    /// <summary>
    /// Initializes the security engine.
    /// </summary>
    public SecurityEngine(ISecurityStore securityStore, ISecurityDataProvider dataProvider)
    {
        _securityStore = securityStore;
        _dataProvider = dataProvider;
    }

    /// <summary>
    /// Evaluates if the current user can access a specific feature.
    /// Hierarchy: Subscription -> Module -> Permission.
    /// </summary>
    public async Task<bool> CanAccessAsync(string moduleCode, string permissionName)
    {
        // 1. Resolve Identity and Context
        var userId = _dataProvider.GetCurrentUserId();
        var tenantId = _dataProvider.GetCurrentTenantId();

        // FAIL-FAST: No context, no access.
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(tenantId)) 
            return false;

        // 2. Validate Active Subscription (Business layer check)
        var hasSubscription = await _securityStore.IsSubscriptionActiveAsync(tenantId);
        if (!hasSubscription) return false;

        // 3. Validate Module availability (Plan layer check)
        var isModuleActive = await _securityStore.IsModuleActiveAsync(tenantId, moduleCode);
        if (!isModuleActive) return false;

        // 4. Role bundle, plus Allow, minus Deny. A stored code is the full
        //    "Module.Permission". A bare permission name still matches so a
        //    caller that has not moved to the full code keeps working.
        var permissions = await EffectivePermissionsAsync(userId);
        var fullCode = moduleCode + "." + permissionName;
        return permissions.Contains(fullCode) || permissions.Contains(permissionName);
    }

    /// <inheritdoc />
    public async Task<List<SecurityMenuItem>> GetAuthorizedMenuAsync(IEnumerable<SecurityMenuItem> fullMenu)
    {
        // 1. Resolve Identity and Context
        var userId = _dataProvider.GetCurrentUserId();
        var tenantId = _dataProvider.GetCurrentTenantId();

        // FAIL-FAST: No context, no menu.
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(tenantId)) 
            return [];

        // 2. Validate Active Subscription (Business layer check - execute once for performance)
        var hasSubscription = await _securityStore.IsSubscriptionActiveAsync(tenantId);
        if (!hasSubscription) return [];

        // 3. BATCH FETCHING (Senior Optimization)
        // Avoid N+1 queries by fetching all modules and permissions into high-performance sets
        var activeModules = (await _securityStore.GetActiveModuleCodesAsync(tenantId))
            .ToFrozenSet(StringComparer.OrdinalIgnoreCase);

        var userPermissions = (await EffectivePermissionsAsync(userId))
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
    public async Task<IEnumerable<string>> GetPermissionsAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId)) 
            return [];

        var permissions = await EffectivePermissionsAsync(userId);
        var tenantId = _dataProvider.GetCurrentTenantId();
        if (string.IsNullOrEmpty(tenantId))
        {
            return permissions;
        }

        var activeModules = (await _securityStore.GetActiveModuleCodesAsync(tenantId))
            .ToFrozenSet(StringComparer.OrdinalIgnoreCase);

        return permissions.Where(code => IsModuleActive(code, activeModules)).ToList();
    }

    /// <summary>
    /// Role permissions from the provider, plus Allow overrides, minus Deny.
    /// Deny is applied last and wins.
    /// </summary>
    private async Task<HashSet<string>> EffectivePermissionsAsync(string userId)
    {
        var granted = await _dataProvider.GetUserPermissionsAsync(userId) ?? [];
        var set = new HashSet<string>(
            granted.Where(code => !string.IsNullOrWhiteSpace(code)),
            StringComparer.OrdinalIgnoreCase);

        var overrides = await _securityStore.GetUserOverridesAsync(userId) ?? [];
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
