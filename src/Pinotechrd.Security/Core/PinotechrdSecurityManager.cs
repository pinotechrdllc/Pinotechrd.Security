using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
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
    /// is outside the code alphabet or names a permission that does not exist, or when the role does not exist.
    /// See <see cref="ReplaceRowsAsync{TParent, TRow}"/> for the transaction, locking and retry rules.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The context has pending changes, or its provider is not relational.
    /// </exception>
    public async Task<bool> AssignPermissionsToRoleAsync(string roleId, IEnumerable<string> permissionCodes)
    {
        if (!Guid.TryParse(roleId, out var roleGuid) || _securityDb is not DbContext dbContext) return false;

        // Every requested code must be valid; whether it exists is checked inside the transaction.
        var wanted = new HashSet<string>(StringComparer.Ordinal);
        foreach (var code in permissionCodes ?? [])
        {
            if (!SecurityCodes.TryNormalize(code, out var normalized)) return false;
            wanted.Add(normalized);
        }

        return await ReplaceRowsAsync<TRole, RolePermission>(
            dbContext,
            nameof(AssignPermissionsToRoleAsync),
            roleGuid,
            rp => rp.RoleId == roleGuid,
            async () =>
            {
                var permissionIds = wanted.Count == 0
                    ? []
                    : await _securityDb.Permissions
                        .Where(p => wanted.Contains(p.Code))
                        .Select(p => p.Id)
                        .ToListAsync();

                return permissionIds.Count != wanted.Count
                    ? null
                    : permissionIds.Select(permissionId => RolePermission.Create(roleGuid, permissionId)).ToList();
            });
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
    /// <remarks>
    /// See <see cref="ReplaceRowsAsync{TParent, TRow}"/> for the transaction, locking and retry rules.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The context has pending changes, or its provider is not relational.
    /// </exception>
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

        return await ReplaceRowsAsync<TUser, UserModulePermission>(
            dbContext,
            nameof(ReplaceUserOverridesAsync),
            userGuid,
            row => row.UserId == userGuid,
            async () =>
            {
                var permissions = wanted.Count == 0
                    ? []
                    : await _securityDb.Permissions.Where(permission => wanted.Contains(permission.Code)).ToListAsync();
                if (permissions.Count != wanted.Count)
                {
                    return null;
                }

                var permissionIdByCode = permissions.ToDictionary(permission => permission.Code, permission => permission.Id, StringComparer.Ordinal);
                return byCode
                    .Select(pair => pair.Value == PermissionAccessType.Deny
                        ? UserModulePermission.CreateDeny(userGuid, permissionIdByCode[pair.Key])
                        : UserModulePermission.CreateAllow(userGuid, permissionIdByCode[pair.Key]))
                    .ToList();
            });
    }

    private const int MaxReplaceAttempts = 5;

    /// <summary>
    /// Replaces every <typeparamref name="TRow"/> owned by one <typeparamref name="TParent"/> row with the rows from
    /// <paramref name="createRows"/>, atomically.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each attempt first runs a no-op <c>UPDATE</c> on the parent row (<c>SET ConcurrencyStamp = ConcurrencyStamp</c>).
    /// That holds the row's write lock until the transaction ends, so a second replace for the same parent waits, then
    /// deletes what the first one committed. Without the lock, two READ COMMITTED transactions could both delete the
    /// old rows and both insert. Then, still holding the lock, it runs <paramref name="createRows"/> (which checks that
    /// the requested permissions exist), deletes the current rows with one set-based <c>DELETE</c> and inserts the new
    /// ones with <c>SaveChanges</c>.
    /// </para>
    /// <para>
    /// Outside any transaction, each attempt runs in its own transaction through the context's execution strategy. A
    /// <see cref="DbUpdateException"/> from <c>SaveChanges</c> (a duplicate pair or a concurrency conflict) rolls the
    /// attempt back and the whole replace runs again, up to <see cref="MaxReplaceAttempts"/> attempts; the last one
    /// propagates. Errors from the lock or the delete (a deadlock, a lock timeout) are not retried here: they propagate
    /// unless the execution strategy treats them as transient.
    /// </para>
    /// <para>
    /// Inside a transaction the caller opened, the replace runs once, without retry, behind a savepoint: a failure
    /// rolls back to the savepoint and propagates, so the caller's transaction keeps the previous rows. When the
    /// provider does not support savepoints, a failure can leave the parent without rows in that transaction, and the
    /// caller must roll it back. Inside a <see cref="System.Transactions.TransactionScope"/> the replace runs once and
    /// the scope owns atomicity; the connection must be enlisted in it (opened inside the scope).
    /// </para>
    /// </remarks>
    /// <returns>
    /// <see langword="false"/>, with nothing changed, when the parent row does not exist or <paramref name="createRows"/>
    /// returns <see langword="null"/>.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// The context has pending changes, or its provider is not relational.
    /// </exception>
    private static async Task<bool> ReplaceRowsAsync<TParent, TRow>(
        DbContext db,
        string operation,
        Guid parentId,
        Expression<Func<TRow, bool>> ownedByParent,
        Func<Task<IReadOnlyList<TRow>?>> createRows)
        where TParent : class
        where TRow : class
    {
        if (!db.Database.IsRelational())
        {
            throw new InvalidOperationException(
                $"{operation} needs a relational database provider, because it runs in a transaction and uses " +
                "ExecuteUpdate and ExecuteDelete.");
        }

        if (db.ChangeTracker.HasChanges())
        {
            throw new InvalidOperationException(
                $"{operation} needs a context without pending changes: save or discard them first, because the " +
                "replace saves the context and may roll it back or retry it.");
        }

        if (db.Database.CurrentTransaction is { } current)
        {
            return await ReplaceRowsInCurrentTransactionAsync<TParent, TRow>(db, current, operation, parentId, ownedByParent, createRows);
        }

        if (System.Transactions.Transaction.Current != null)
        {
            // The TransactionScope owns atomicity; an execution strategy cannot retry inside it.
            return await ReplaceRowsOnceAsync<TParent, TRow>(db, parentId, ownedByParent, createRows);
        }

        var strategy = db.Database.CreateExecutionStrategy();
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await strategy.ExecuteAsync(async () =>
                {
                    await using var transaction = await db.Database.BeginTransactionAsync();
                    if (!await ReplaceRowsOnceAsync<TParent, TRow>(db, parentId, ownedByParent, createRows))
                    {
                        await transaction.RollbackAsync();
                        return false;
                    }

                    await transaction.CommitAsync();
                    return true;
                });
            }
            catch (DbUpdateException) when (attempt < MaxReplaceAttempts)
            {
                // The transaction was rolled back when it was disposed; run the whole replace again.
            }
        }
    }

    private static async Task<bool> ReplaceRowsInCurrentTransactionAsync<TParent, TRow>(
        DbContext db,
        IDbContextTransaction transaction,
        string operation,
        Guid parentId,
        Expression<Func<TRow, bool>> ownedByParent,
        Func<Task<IReadOnlyList<TRow>?>> createRows)
        where TParent : class
        where TRow : class
    {
        if (!transaction.SupportsSavepoints)
        {
            // Without savepoints a failure cannot be undone here; the caller must roll back its transaction.
            return await ReplaceRowsOnceAsync<TParent, TRow>(db, parentId, ownedByParent, createRows);
        }

        const string savepoint = "pinotechrd_replace";
        await transaction.CreateSavepointAsync(savepoint);
        bool replaced;
        try
        {
            replaced = await ReplaceRowsOnceAsync<TParent, TRow>(db, parentId, ownedByParent, createRows);
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
                    $"{operation} failed, and rolling back to its savepoint failed too; roll back the transaction.",
                    original,
                    rollbackFailure);
            }

            throw;
        }

        if (replaced)
        {
            await transaction.ReleaseSavepointAsync(savepoint);
        }
        else
        {
            await transaction.RollbackToSavepointAsync(savepoint);
        }

        return replaced;
    }

    private static async Task<bool> ReplaceRowsOnceAsync<TParent, TRow>(
        DbContext db,
        Guid parentId,
        Expression<Func<TRow, bool>> ownedByParent,
        Func<Task<IReadOnlyList<TRow>?>> createRows)
        where TParent : class
        where TRow : class
    {
        var locked = await db.Set<TParent>()
            .Where(parent => EF.Property<Guid>(parent, "Id") == parentId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(
                parent => EF.Property<string?>(parent, "ConcurrencyStamp"),
                parent => EF.Property<string?>(parent, "ConcurrencyStamp")));
        if (locked == 0) return false;

        // Checked under the lock, so a permission deleted since the caller's request returns false.
        var rows = await createRows();
        if (rows == null) return false;

        // The DELETE below bypasses the change tracker: stop tracking the rows it removes.
        var isOwned = ownedByParent.Compile();
        foreach (var entry in db.ChangeTracker.Entries<TRow>().Where(entry => isOwned(entry.Entity)).ToList())
        {
            entry.State = EntityState.Detached;
        }

        await db.Set<TRow>().Where(ownedByParent).ExecuteDeleteAsync();

        db.Set<TRow>().AddRange(rows);
        try
        {
            await db.SaveChangesAsync();
        }
        catch
        {
            // Leave nothing of this attempt pending in the context.
            foreach (var row in rows)
            {
                db.Entry(row).State = EntityState.Detached;
            }

            throw;
        }

        return true;
    }

    #endregion
}
