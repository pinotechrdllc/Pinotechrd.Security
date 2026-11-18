using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Database implementation of ISecurityStore.
/// </summary>
public class DbSecurityStore : ISecurityStore
{
    private readonly ISecurityDbContext _db;

    /// <summary>
    /// Initializes a new instance of the <see cref="DbSecurityStore"/> class.
    /// </summary>
    /// <param name="db">The security database context.</param>
    public DbSecurityStore(ISecurityDbContext db)
    {
        _db = db;
    }

    /// <inheritdoc />
    public async Task<bool> IsSubscriptionActiveAsync(string tenantId)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        return await _db.SystemSubscriptions
            .AnyAsync(s => s.TenantName == tenantId && s.IsActive && s.StartDate <= today && (!s.EndDate.HasValue || s.EndDate >= today));
    }

    /// <inheritdoc />
    public async Task<bool> IsModuleActiveAsync(string tenantId, string moduleCode)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        if (!SecurityCodes.TryNormalize(moduleCode, out var code)) return false;

        // EF Core 10 optimizes this hierarchical join across schemas
        return await (from sub in _db.SystemSubscriptions
                      join map in _db.SubscriptionPlanModules on sub.PlanId equals map.PlanId
                      join mod in _db.Modules on map.ModuleId equals mod.Id
                      where sub.TenantName == tenantId
                            && sub.IsActive
                            && sub.StartDate <= today && (!sub.EndDate.HasValue || sub.EndDate >= today)
                            && mod.Code == code
                            && mod.IsActive
                      select mod.Id)
                      .AnyAsync();
    }

    /// <inheritdoc />
    public async Task<IEnumerable<string>> GetActiveModuleCodesAsync(string tenantId)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);

        // Pre-fetch all active module codes for the tenant to support O(1) filtering
        return await (from sub in _db.SystemSubscriptions
                      join map in _db.SubscriptionPlanModules on sub.PlanId equals map.PlanId
                      join mod in _db.Modules on map.ModuleId equals mod.Id
                      where sub.TenantName == tenantId
                            && sub.IsActive
                            && sub.StartDate <= today && (!sub.EndDate.HasValue || sub.EndDate >= today)
                            && mod.IsActive
                      select mod.Code)
                      .TagWith("SecurityStore.GetActiveModuleCodes")
                      .AsNoTracking()
                      .ToListAsync();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SecurityModule>> GetActiveCatalogAsync(string tenantId)
    {
        var codes = (await GetActiveModuleCodesAsync(tenantId)).ToList();
        if (codes.Count == 0)
        {
            return [];
        }

        var modules = await _db.Modules
            .Where(module => module.IsActive && codes.Contains(module.Code))
            .OrderBy(module => module.DisplayOrder)
            .AsNoTracking()
            .ToListAsync();

        var moduleIds = modules.Select(module => module.Id).ToList();
        var permissions = await _db.Permissions
            .Where(permission => permission.IsActive && moduleIds.Contains(permission.ModuleId))
            .AsNoTracking()
            .ToListAsync();

        foreach (var module in modules)
        {
            module.Permissions = permissions.Where(permission => permission.ModuleId == module.Id).ToList();
        }

        return modules;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<UserPermissionOverride>> GetUserOverridesAsync(string userId)
    {
        if (!Guid.TryParse(userId, out var userGuid))
        {
            return [];
        }

        return await _db.UserModulePermissions
            .Where(row => row.UserId == userGuid)
            .Select(row => new UserPermissionOverride(row.Permission.Code, row.AccessType))
            .ToListAsync();
    }
}
