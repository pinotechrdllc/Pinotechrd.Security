using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Implementation of the Pinotechrd Security Manager.
/// Provides a centralized way to handle User and Role administration.
/// </summary>
/// <typeparam name="TUser">The identity user type.</typeparam>
/// <typeparam name="TRole">The identity role type.</typeparam>
public class PinotechrdSecurityManager<TUser, TRole> : IPinotechrdSecurityManager<TUser, TRole>
    where TUser : class
    where TRole : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly RoleManager<TRole> _roleManager;
    private readonly ISecurityDbContext _securityDb;
    private readonly IRefreshTokenStore? _refreshTokenStore;

    /// <summary>
    /// Initializes the security manager.
    /// </summary>
    /// <remarks>
    /// Without <paramref name="refreshTokenStore"/>, deactivating a user cannot revoke its refresh tokens;
    /// refresh still fails for an inactive user. <c>AddPinotechrdSecurity</c> registers the store.
    /// </remarks>
    public PinotechrdSecurityManager(
        UserManager<TUser> userManager,
        RoleManager<TRole> roleManager,
        ISecurityDbContext securityDb,
        IRefreshTokenStore? refreshTokenStore = null)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _securityDb = securityDb;
        _refreshTokenStore = refreshTokenStore;
    }

    #region User Management

    /// <inheritdoc />
    public async Task<IEnumerable<TUser>> GetUsersAsync()
    {
        return await _userManager.Users.ToListAsync();
    }

    /// <inheritdoc />
    public async Task<TUser?> GetUserByIdAsync(string userId)
    {
        return await _userManager.FindByIdAsync(userId);
    }

    /// <inheritdoc />
    public async Task<TUser?> GetUserByEmailAsync(string email)
    {
        return await _userManager.FindByEmailAsync(email);
    }

    /// <inheritdoc />
    public async Task<bool> CreateUserAsync(TUser user, string password, IEnumerable<string>? roles = null)
    {
        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded) return false;

        if (roles != null && roles.Any())
        {
            await _userManager.AddToRolesAsync(user, roles);
        }

        return true;
    }

    /// <inheritdoc />
    public async Task<bool> UpdateUserAsync(TUser user)
    {
        var result = await _userManager.UpdateAsync(user);
        return result.Succeeded;
    }

    /// <inheritdoc />
    /// <remarks>
    /// The user's refresh tokens are revoked before the user is deleted. If revocation throws, the exception
    /// propagates and the user is not deleted. If the delete then fails, the method returns <c>false</c> and the
    /// tokens stay revoked. Access tokens already issued stay valid until they expire.
    /// </remarks>
    public async Task<bool> DeleteUserAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        // Revoke under the stored id: tokens are saved under GetUserIdAsync, and FindByIdAsync also accepts
        // other spellings of the same id (upper case, braces), which the store would not match.
        if (_refreshTokenStore != null) await _refreshTokenStore.RevokeAllForUserAsync(await _userManager.GetUserIdAsync(user));

        var result = await _userManager.DeleteAsync(user);
        return result.Succeeded;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Deactivating a user also revokes all its refresh tokens and renews its security stamp, which invalidates
    /// pending two-factor, reset and confirmation tokens. Access tokens already issued stay valid until they expire.
    /// </remarks>
    public async Task<bool> SetUserActiveStatusAsync(string userId, bool isActive)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        // Try to access IsActive if it's a BaseSecurityUser
        if (user is BaseSecurityUser securityUser)
        {
            securityUser.IsActive = isActive;
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded) return false;

            if (!isActive)
            {
                if (_refreshTokenStore != null) await _refreshTokenStore.RevokeAllForUserAsync(await _userManager.GetUserIdAsync(user));
                if (_userManager.SupportsUserSecurityStamp)
                {
                    var stampResult = await _userManager.UpdateSecurityStampAsync(user);
                    if (!stampResult.Succeeded) return false;
                }
            }

            return true;
        }

        return false;
    }

    /// <inheritdoc />
    public async Task<bool> ResetUserPasswordAsync(string userId, string newPassword)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        return result.Succeeded;
    }

    /// <inheritdoc />
    public async Task<bool> ChangeUserPasswordAsync(string userId, string currentPassword, string newPassword)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
        return result.Succeeded;
    }

    #endregion

    #region Role Management

    /// <inheritdoc />
    public async Task<IEnumerable<TRole>> GetRolesAsync()
    {
        return await _roleManager.Roles.ToListAsync();
    }

    /// <inheritdoc />
    public async Task<TRole?> GetRoleByIdAsync(string roleId)
    {
        return await _roleManager.FindByIdAsync(roleId);
    }

    /// <inheritdoc />
    public async Task<TRole?> GetRoleByNameAsync(string roleName)
    {
        return await _roleManager.FindByNameAsync(roleName);
    }

    /// <inheritdoc />
    public async Task<bool> CreateRoleAsync(TRole role, string? description = null)
    {
        if (role is BaseSecurityRole securityRole && !string.IsNullOrEmpty(description))
        {
            securityRole.Description = description;
        }

        var result = await _roleManager.CreateAsync(role);
        return result.Succeeded;
    }

    /// <inheritdoc />
    public async Task<bool> UpdateRoleAsync(TRole role)
    {
        var result = await _roleManager.UpdateAsync(role);
        return result.Succeeded;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteRoleAsync(string roleId)
    {
        var role = await _roleManager.FindByIdAsync(roleId);
        if (role == null) return false;

        var result = await _roleManager.DeleteAsync(role);
        return result.Succeeded;
    }

    #endregion

    #region User-Role Relationships

    /// <inheritdoc />
    public async Task<IEnumerable<string>> GetUserRolesAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return Enumerable.Empty<string>();

        return await _userManager.GetRolesAsync(user);
    }

    /// <inheritdoc />
    public async Task<bool> AssignRolesToUserAsync(string userId, IEnumerable<string> roleNames)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        var result = await _userManager.AddToRolesAsync(user, roleNames);
        return result.Succeeded;
    }

    /// <inheritdoc />
    public async Task<bool> RemoveRolesFromUserAsync(string userId, IEnumerable<string> roleNames)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        var result = await _userManager.RemoveFromRolesAsync(user, roleNames);
        return result.Succeeded;
    }

    #endregion

    #region Permission Management

    /// <inheritdoc />
    public async Task<IEnumerable<SecurityPermission>> GetPermissionsAsync()
    {
        return await _securityDb.Permissions
            .Include(p => p.Module)
            .OrderBy(p => p.Module.DisplayOrder)
            .ThenBy(p => p.Name)
            .ToListAsync();
    }

    /// <inheritdoc />
    public async Task<IEnumerable<string>> GetRolePermissionsAsync(string roleId)
    {
        if (!Guid.TryParse(roleId, out var roleGuid)) return Enumerable.Empty<string>();

        return await _securityDb.RolePermissions
            .Where(rp => rp.RoleId == roleGuid)
            .Select(rp => rp.Permission.Code)
            .ToListAsync();
    }

    /// <inheritdoc />
    /// <remarks>
    /// Codes are normalised (trimmed, upper case). Returns <see langword="false"/> and changes nothing when a code
    /// is outside the code alphabet or names a permission that does not exist.
    /// </remarks>
    public async Task<bool> AssignPermissionsToRoleAsync(string roleId, IEnumerable<string> permissionCodes)
    {
        if (!Guid.TryParse(roleId, out var roleGuid)) return false;

        // Verify role existence
        var role = await _roleManager.FindByIdAsync(roleId);
        if (role == null) return false;

        try
        {
            // 1. Get current assignments
            // Since ISecurityDbContext only has IQueryable, we might need to cast to DbContext to use the DbSet for removal
            // but the implementation PinotechrdSecurityDbContext IS a DbContext.
            if (_securityDb is DbContext dbContext)
            {
                // 1. Every requested code must be valid and exist; otherwise nothing changes.
                var wanted = new HashSet<string>(StringComparer.Ordinal);
                foreach (var code in permissionCodes ?? [])
                {
                    if (!SecurityCodes.TryNormalize(code, out var normalized)) return false;
                    wanted.Add(normalized);
                }

                var permissionIds = wanted.Count == 0
                    ? []
                    : await _securityDb.Permissions
                        .Where(p => wanted.Contains(p.Code))
                        .Select(p => p.Id)
                        .ToListAsync();

                if (permissionIds.Count != wanted.Count) return false;

                // 2. Replace the current assignments
                var currentAssignments = await dbContext.Set<RolePermission>()
                    .Where(rp => rp.RoleId == roleGuid)
                    .ToListAsync();
                dbContext.Set<RolePermission>().RemoveRange(currentAssignments);

                foreach (var permissionId in permissionIds)
                {
                    dbContext.Set<RolePermission>().Add(RolePermission.Create(roleGuid, permissionId));
                }

                await _securityDb.SaveChangesAsync();
                return true;
            }

            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SecurityModule>> GetActiveCatalogAsync(string tenantId)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var codes = await (from sub in _securityDb.SystemSubscriptions
                           join map in _securityDb.SubscriptionPlanModules on sub.PlanId equals map.PlanId
                           join mod in _securityDb.Modules on map.ModuleId equals mod.Id
                           where sub.TenantName == tenantId
                                 && sub.IsActive
                                 && sub.StartDate <= today
                                 && (!sub.EndDate.HasValue || sub.EndDate >= today)
                                 && mod.IsActive
                           select mod.Code).ToListAsync();

        if (codes.Count == 0)
        {
            return [];
        }

        var modules = await _securityDb.Modules
            .Where(module => module.IsActive && codes.Contains(module.Code))
            .OrderBy(module => module.DisplayOrder)
            .ToListAsync();
        var moduleIds = modules.Select(module => module.Id).ToList();
        var permissions = await _securityDb.Permissions
            .Where(permission => permission.IsActive && moduleIds.Contains(permission.ModuleId))
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

        return await _securityDb.UserModulePermissions
            .Where(row => row.UserId == userGuid)
            .Select(row => new UserPermissionOverride(row.Permission.Code, row.AccessType))
            .ToListAsync();
    }

    /// <inheritdoc />
    public async Task<bool> ReplaceUserOverridesAsync(string userId, IEnumerable<UserPermissionOverride> overrides)
    {
        if (!Guid.TryParse(userId, out var userGuid) || _securityDb is not DbContext dbContext)
        {
            return false;
        }

        var byCode = new Dictionary<string, PermissionAccessType>(StringComparer.Ordinal);
        foreach (var item in overrides ?? [])
        {
            if (string.IsNullOrWhiteSpace(item.Code))
            {
                continue;
            }

            if (!SecurityCodes.TryNormalize(item.Code, out var code))
            {
                return false;
            }

            if (byCode.TryGetValue(code, out var current) && current == PermissionAccessType.Deny)
            {
                continue;
            }

            byCode[code] = item.Access;
        }

        var wanted = byCode.Keys.ToList();
        var permissions = wanted.Count == 0
            ? []
            : await _securityDb.Permissions.Where(permission => wanted.Contains(permission.Code)).ToListAsync();
        if (permissions.Count != wanted.Count)
        {
            return false;
        }

        var existing = await dbContext.Set<UserModulePermission>()
            .Where(row => row.UserId == userGuid)
            .ToListAsync();
        dbContext.Set<UserModulePermission>().RemoveRange(existing);

        foreach (var (code, access) in byCode)
        {
            var permission = permissions.First(item => string.Equals(item.Code, code, StringComparison.Ordinal));
            var row = access == PermissionAccessType.Deny
                ? UserModulePermission.CreateDeny(userGuid, permission.Id)
                : UserModulePermission.CreateAllow(userGuid, permission.Id);
            dbContext.Set<UserModulePermission>().Add(row);
        }

        await _securityDb.SaveChangesAsync();
        return true;
    }

    #endregion
}
