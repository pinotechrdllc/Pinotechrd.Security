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
    public async Task<bool> IsSubscriptionActiveAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        return await _db.SystemSubscriptions
            .AnyAsync(s => s.TenantName == tenantId && s.IsActive && s.StartDate <= today && (!s.EndDate.HasValue || s.EndDate >= today), cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> IsModuleActiveAsync(string tenantId, string moduleCode, CancellationToken cancellationToken = default)
    {
        if (!SecurityCodes.TryNormalize(moduleCode, out var code)) return false;

        var modules = await PlanModulesAsync(_db, tenantId, cancellationToken);
        return modules.Any(module => module.Code == code);
    }

    /// <summary>
    /// The tenant's active modules that an active subscription's plan includes, as their id and normalised code.
    /// A module row counts only when <see cref="SecurityModuleId.IsIdOf"/> holds: the plan mapping lives in the shared
    /// catalog and refers to a module by id, so a row in the tenant schema whose code does not belong to its id (changed
    /// after creation, or a random id from before deterministic ids) is not that module. Codes are compared normalised
    /// (trimmed, upper case), as everywhere else in the library.
    /// </summary>
    internal static async Task<List<(Guid Id, string Code)>> PlanModulesAsync(ISecurityDbContext db, string tenantId, CancellationToken cancellationToken)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var rows = await (from sub in db.SystemSubscriptions
                          join map in db.SubscriptionPlanModules on sub.PlanId equals map.PlanId
                          join mod in db.Modules on map.ModuleId equals mod.Id
                          where sub.TenantName == tenantId
                                && sub.IsActive
                                && sub.StartDate <= today && (!sub.EndDate.HasValue || sub.EndDate >= today)
                                && mod.IsActive
                          select new { mod.Id, mod.Code })
                          .TagWith("SecurityStore.PlanModules")
                          .AsNoTracking()
                          .ToListAsync(cancellationToken);

        var result = new List<(Guid Id, string Code)>();
        foreach (var row in rows)
        {
            if (SecurityModuleId.IsIdOf(row.Id, row.Code)
                && SecurityCodes.TryNormalize(row.Code, out var normalized)
                && !result.Exists(module => module.Id == row.Id))
            {
                result.Add((row.Id, normalized));
            }
        }

        return result;
    }

    /// <inheritdoc />
    /// <remarks>The codes are normalised (trimmed, upper case).</remarks>
    public async Task<IEnumerable<string>> GetActiveModuleCodesAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        // Pre-fetch all active module codes for the tenant to support O(1) filtering
        return (await PlanModulesAsync(_db, tenantId, cancellationToken)).Select(module => module.Code).ToList();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SecurityModule>> GetActiveCatalogAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        var ids = (await PlanModulesAsync(_db, tenantId, cancellationToken)).Select(module => module.Id).ToList();
        if (ids.Count == 0)
        {
            return [];
        }

        var modules = await _db.Modules
            .Where(module => module.IsActive && ids.Contains(module.Id))
            .OrderBy(module => module.DisplayOrder)
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        var moduleIds = modules.Select(module => module.Id).ToList();
        var permissions = await _db.Permissions
            .Where(permission => permission.IsActive && moduleIds.Contains(permission.ModuleId))
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        foreach (var module in modules)
        {
            module.Permissions = permissions.Where(permission => permission.ModuleId == module.Id).ToList();
        }

        return modules;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<UserPermissionOverride>> GetUserOverridesAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(userId, out var userGuid))
        {
            return [];
        }

        return await _db.UserModulePermissions
            .Where(row => row.UserId == userGuid)
            .Select(row => new UserPermissionOverride(row.Permission.Code, row.AccessType))
            .ToListAsync(cancellationToken);
    }
}
