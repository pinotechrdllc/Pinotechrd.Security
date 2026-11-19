using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
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
    /// <remarks>
    /// Without a caller transaction, a relational context writes the user and its roles in one transaction run
    /// through the context's execution strategy, so a retrying strategy repeats the whole unit. If the commit
    /// reports a transient error, the strategy checks whether the user and its roles were stored before retrying,
    /// and returns <c>true</c> when they were. When the context already has a transaction, the work runs inside
    /// it behind a savepoint; a failure rolls back to that savepoint only and the caller still owns the commit.
    /// Inside a <see cref="System.Transactions.TransactionScope"/> the work enlists in the scope, which is rolled
    /// back only if the caller abandons it. A caller transaction on a provider without savepoints, and a
    /// non-relational context, get no rollback. On a relational context the method throws
    /// <see cref="InvalidOperationException"/> when the context has pending changes, because the Identity store
    /// saves every pending change of the context in this unit and a rollback would lose them. After a failure the
    /// entities the attempt added to the change tracker are detached, so a later <c>SaveChanges</c> does not write
    /// them again.
    /// </remarks>
    public async Task<bool> CreateUserAsync(TUser user, string password, IEnumerable<string>? roles = null)
    {
        var roleNames = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var roleName in roles ?? [])
        {
            if (string.IsNullOrWhiteSpace(roleName)) return false;
            if (seen.Add(NormalizeRole(roleName))) roleNames.Add(roleName);
        }

        if (_securityDb is not DbContext context || !context.Database.IsRelational())
        {
            return await CreateUserWithRolesAsync(user, password, roleNames);
        }

        if (context.ChangeTracker.HasChanges())
        {
            throw new InvalidOperationException(
                "CreateUserAsync needs a context without pending changes: save or discard them first, because a " +
                "rollback would lose them.");
        }

        var tracked = TrackedEntities(context);

        if (context.Database.CurrentTransaction is { } current)
        {
            return await CreateUserInCurrentTransactionAsync(context, current, tracked, user, password, roleNames);
        }

        if (System.Transactions.Transaction.Current != null)
        {
            // The TransactionScope owns atomicity; an execution strategy cannot retry inside it.
            return await RunAndDetachOnFailureAsync(context, tracked, () => CreateUserWithRolesAsync(user, password, roleNames));
        }

        var strategy = context.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(
            0,
            async (_, _, cancellationToken) =>
            {
                await using var transaction = await context.Database.BeginTransactionAsync(cancellationToken);
                return await RunAndDetachOnFailureAsync(context, tracked, async () =>
                {
                    if (!await CreateUserWithRolesAsync(user, password, roleNames))
                    {
                        await transaction.RollbackAsync(cancellationToken);
                        return false;
                    }

                    await transaction.CommitAsync(cancellationToken);
                    return true;
                });
            },
            async (_, _, _) =>
            {
                // Called after a transient error: the commit may have reached the database before the error.
                var stored = await UserExistsWithRolesAsync(context, tracked, user, roleNames);
                return new ExecutionResult<bool>(stored, stored);
            },
            CancellationToken.None);
    }

    private async Task<bool> CreateUserInCurrentTransactionAsync(
        DbContext context,
        IDbContextTransaction transaction,
        HashSet<object> tracked,
        TUser user,
        string password,
        IReadOnlyCollection<string> roleNames)
    {
        if (!transaction.SupportsSavepoints)
        {
            // Without savepoints a failure cannot be undone here; the caller must roll back its transaction.
            return await RunAndDetachOnFailureAsync(context, tracked, () => CreateUserWithRolesAsync(user, password, roleNames));
        }

        const string savepoint = "pinotechrd_create_user";
        await transaction.CreateSavepointAsync(savepoint);
        bool created;
        try
        {
            created = await RunAndDetachOnFailureAsync(context, tracked, () => CreateUserWithRolesAsync(user, password, roleNames));
        }
        catch (Exception original)
        {
            try
            {
                await transaction.RollbackToSavepointAsync(savepoint);
            }
            catch (Exception rollbackFailure)
            {
                throw new AggregateException(
                    "CreateUserAsync failed, and rolling back to its savepoint failed too; roll back the transaction.",
                    original,
                    rollbackFailure);
            }

            throw;
        }

        if (created)
        {
            await transaction.ReleaseSavepointAsync(savepoint);
        }
        else
        {
            await transaction.RollbackToSavepointAsync(savepoint);
        }

        return created;
    }

    private async Task<bool> CreateUserWithRolesAsync(TUser user, string password, IReadOnlyCollection<string> roleNames)
    {
        // Checked in every attempt, inside its transaction, so a role deleted since an earlier attempt returns false.
        foreach (var roleName in roleNames)
        {
            if (!await _roleManager.RoleExistsAsync(roleName)) return false;
        }

        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded) return false;

        if (roleNames.Count == 0) return true;

        var rolesResult = await _userManager.AddToRolesAsync(user, roleNames);
        return rolesResult.Succeeded;
    }

    /// <summary>
    /// Whether <paramref name="user"/> is stored with every role in <paramref name="roleNames"/>. Entities the check
    /// loads are detached again.
    /// </summary>
    private async Task<bool> UserExistsWithRolesAsync(
        DbContext context,
        HashSet<object> tracked,
        TUser user,
        IReadOnlyCollection<string> roleNames)
    {
        try
        {
            var stored = await _userManager.FindByIdAsync(await _userManager.GetUserIdAsync(user));
            if (stored == null) return false;

            var assigned = (await _userManager.GetRolesAsync(stored)).Select(NormalizeRole).ToHashSet(StringComparer.Ordinal);
            return roleNames.All(roleName => assigned.Contains(NormalizeRole(roleName)));
        }
        finally
        {
            DetachUntracked(context, tracked);
        }
    }

    private string NormalizeRole(string roleName) => _roleManager.NormalizeKey(roleName) ?? roleName;

    /// <summary>
    /// Runs <paramref name="operation"/> and, when it returns <c>false</c> or throws, detaches every entity it added
    /// to the change tracker. Their rows are rolled back (or never committed), so they must not be saved later.
    /// </summary>
    private static async Task<bool> RunAndDetachOnFailureAsync(DbContext context, HashSet<object> tracked, Func<Task<bool>> operation)
    {
        try
        {
            if (await operation()) return true;
        }
        catch
        {
            DetachUntracked(context, tracked);
            throw;
        }

        DetachUntracked(context, tracked);
        return false;
    }

    private static HashSet<object> TrackedEntities(DbContext context) =>
        context.ChangeTracker.Entries().Select(e => e.Entity).ToHashSet(ReferenceEqualityComparer.Instance);

    private static void DetachUntracked(DbContext context, HashSet<object> tracked)
    {
        foreach (var entry in context.ChangeTracker.Entries().ToList())
        {
            if (!tracked.Contains(entry.Entity)) entry.State = EntityState.Detached;
        }
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
