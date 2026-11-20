using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
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
    public async Task<IEnumerable<TUser>> GetUsersAsync(CancellationToken cancellationToken = default)
    {
        return await _userManager.Users.ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<TUser?> GetUserByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await _userManager.FindByIdAsync(userId);
    }

    /// <inheritdoc />
    public async Task<TUser?> GetUserByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
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
    public async Task<bool> CreateUserAsync(TUser user, string password, IEnumerable<string>? roles = null, CancellationToken cancellationToken = default)
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
            return await CreateUserWithRolesAsync(user, password, roleNames, canRollBack: false, cancellationToken);
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
            return await CreateUserInCurrentTransactionAsync(context, current, tracked, user, password, roleNames, cancellationToken);
        }

        if (System.Transactions.Transaction.Current != null)
        {
            // The TransactionScope owns atomicity; an execution strategy cannot retry inside it.
            return await RunAndDetachOnFailureAsync(context, tracked, () => CreateUserWithRolesAsync(user, password, roleNames, canRollBack: true, cancellationToken));
        }

        var strategy = context.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(
            0,
            async (_, _, ct) =>
            {
                await using var transaction = await context.Database.BeginTransactionAsync(ct);
                return await RunAndDetachOnFailureAsync(context, tracked, async () =>
                {
                    if (!await CreateUserWithRolesAsync(user, password, roleNames, canRollBack: true, ct))
                    {
                        await transaction.RollbackAsync(ct);
                        return false;
                    }

                    // The work is done: a cancelled commit would leave its outcome unknown.
                    await transaction.CommitAsync(CancellationToken.None);
                    return true;
                });
            },
            async (_, _, ct) =>
            {
                // Called after a transient error: the commit may have reached the database before the error.
                var stored = await UserExistsWithRolesAsync(context, tracked, user, roleNames, ct);
                return new ExecutionResult<bool>(stored, stored);
            },
            cancellationToken);
    }

    private async Task<bool> CreateUserInCurrentTransactionAsync(
        DbContext context,
        IDbContextTransaction transaction,
        HashSet<object> tracked,
        TUser user,
        string password,
        IReadOnlyCollection<string> roleNames,
        CancellationToken cancellationToken)
    {
        return await SavepointScope.RunAsync(
            transaction,
            "pinotechrd_create_user",
            "CreateUserAsync",
            () => RunAndDetachOnFailureAsync(context, tracked, () => CreateUserWithRolesAsync(user, password, roleNames, transaction.SupportsSavepoints, cancellationToken)),
            cancellationToken);
    }

    private async Task<bool> CreateUserWithRolesAsync(
        TUser user,
        string password,
        IReadOnlyCollection<string> roleNames,
        bool canRollBack,
        CancellationToken cancellationToken)
    {
        // Checked in every attempt, inside its transaction, so a role deleted since an earlier attempt returns false.
        foreach (var roleName in roleNames)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!await _roleManager.RoleExistsAsync(roleName)) return false;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded) return false;

        if (roleNames.Count == 0) return true;

        // Without a rollback, a cancellation here would leave the user created without its roles.
        if (canRollBack) cancellationToken.ThrowIfCancellationRequested();
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
        IReadOnlyCollection<string> roleNames,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var stored = await _userManager.FindByIdAsync(await _userManager.GetUserIdAsync(user));
            if (stored == null) return false;

            cancellationToken.ThrowIfCancellationRequested();
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
    public async Task<bool> UpdateUserAsync(TUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = await _userManager.UpdateAsync(user);
        return result.Succeeded;
    }

    /// <inheritdoc />
    /// <remarks>
    /// The user's refresh tokens are revoked before the user is deleted. If revocation throws, the exception
    /// propagates and the user is not deleted. If the delete then fails, the method returns <c>false</c> and the
    /// tokens stay revoked. Access tokens already issued stop working once the user is deleted, with
    /// <c>JwtSettings.ValidateSecurityStamp</c> on (the default); otherwise when they expire.
    /// </remarks>
    public async Task<bool> DeleteUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        // Revoke under the stored id: tokens are saved under GetUserIdAsync, and FindByIdAsync also accepts
        // other spellings of the same id (upper case, braces), which the store would not match.
        // Last cancellation point: once revocation starts, it and the delete run to the end, so a cancelled request
        // cannot leave the tokens half revoked.
        cancellationToken.ThrowIfCancellationRequested();
        if (_refreshTokenStore != null) await _refreshTokenStore.RevokeAllForUserAsync(await _userManager.GetUserIdAsync(user), CancellationToken.None);

        var result = await _userManager.DeleteAsync(user);
        return result.Succeeded;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Deactivating a user also revokes all its refresh tokens and renews its security stamp, which invalidates
    /// pending two-factor, reset and confirmation tokens. Access tokens already issued stop working at once with
    /// <c>JwtSettings.ValidateSecurityStamp</c> on (the default); otherwise when they expire.
    /// </remarks>
    public async Task<bool> SetUserActiveStatusAsync(string userId, bool isActive, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        // Try to access IsActive if it's a BaseSecurityUser
        if (user is BaseSecurityUser securityUser)
        {
            cancellationToken.ThrowIfCancellationRequested();
            securityUser.IsActive = isActive;
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded) return false;

            if (!isActive)
            {
                // The user is already stored inactive: finish the revocation even if the request is cancelled.
                if (_refreshTokenStore != null) await _refreshTokenStore.RevokeAllForUserAsync(await _userManager.GetUserIdAsync(user), CancellationToken.None);
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
    public async Task<bool> RevokeUserSessionsAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (_refreshTokenStore == null) return false;

        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        // Revoke under the stored id: FindByIdAsync also accepts other spellings of the same id.
        // Last cancellation point: the revocation and the stamp renewal then run to the end.
        cancellationToken.ThrowIfCancellationRequested();
        await _refreshTokenStore.RevokeAllForUserAsync(await _userManager.GetUserIdAsync(user), CancellationToken.None);
        if (!_userManager.SupportsUserSecurityStamp) return true;

        var stampResult = await _userManager.UpdateSecurityStampAsync(user);
        return stampResult.Succeeded;
    }

    /// <inheritdoc />
    public async Task<bool> ResetUserPasswordAsync(string userId, string newPassword, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        cancellationToken.ThrowIfCancellationRequested();
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        return result.Succeeded;
    }

    /// <inheritdoc />
    public async Task<bool> ChangeUserPasswordAsync(string userId, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        cancellationToken.ThrowIfCancellationRequested();
        var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
        return result.Succeeded;
    }

    #endregion

    #region Role Management

    /// <inheritdoc />
    public async Task<IEnumerable<TRole>> GetRolesAsync(CancellationToken cancellationToken = default)
    {
        return await _roleManager.Roles.ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<TRole?> GetRoleByIdAsync(string roleId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await _roleManager.FindByIdAsync(roleId);
    }

    /// <inheritdoc />
    public async Task<TRole?> GetRoleByNameAsync(string roleName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await _roleManager.FindByNameAsync(roleName);
    }

    /// <inheritdoc />
    public async Task<bool> CreateRoleAsync(TRole role, string? description = null, CancellationToken cancellationToken = default)
    {
        if (role is BaseSecurityRole securityRole && !string.IsNullOrEmpty(description))
        {
            securityRole.Description = description;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var result = await _roleManager.CreateAsync(role);
        return result.Succeeded;
    }

    /// <inheritdoc />
    public async Task<bool> UpdateRoleAsync(TRole role, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = await _roleManager.UpdateAsync(role);
        return result.Succeeded;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteRoleAsync(string roleId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var role = await _roleManager.FindByIdAsync(roleId);
        if (role == null) return false;

        cancellationToken.ThrowIfCancellationRequested();
        var result = await _roleManager.DeleteAsync(role);
        return result.Succeeded;
    }

    #endregion

    #region User-Role Relationships

    /// <inheritdoc />
    public async Task<IEnumerable<string>> GetUserRolesAsync(string userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return Enumerable.Empty<string>();

        cancellationToken.ThrowIfCancellationRequested();
        return await _userManager.GetRolesAsync(user);
    }

    /// <inheritdoc />
    public async Task<bool> AssignRolesToUserAsync(string userId, IEnumerable<string> roleNames, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        cancellationToken.ThrowIfCancellationRequested();
        var result = await _userManager.AddToRolesAsync(user, roleNames);
        return result.Succeeded;
    }

    /// <inheritdoc />
    public async Task<bool> RemoveRolesFromUserAsync(string userId, IEnumerable<string> roleNames, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        cancellationToken.ThrowIfCancellationRequested();
        var result = await _userManager.RemoveFromRolesAsync(user, roleNames);
        return result.Succeeded;
    }

    #endregion

    #region Permission Management

    /// <inheritdoc />
    public async Task<IEnumerable<SecurityPermission>> GetPermissionsAsync(CancellationToken cancellationToken = default)
    {
        return await _securityDb.Permissions
            .Include(p => p.Module)
            .OrderBy(p => p.Module.DisplayOrder)
            .ThenBy(p => p.Name)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<string>> GetRolePermissionsAsync(string roleId, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(roleId, out var roleGuid)) return Enumerable.Empty<string>();

        return await _securityDb.RolePermissions
            .Where(rp => rp.RoleId == roleGuid)
            .Select(rp => rp.Permission.Code)
            .ToListAsync(cancellationToken);
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
    public async Task<bool> AssignPermissionsToRoleAsync(string roleId, IEnumerable<string> permissionCodes, CancellationToken cancellationToken = default)
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
                        .ToListAsync(cancellationToken);

                return permissionIds.Count != wanted.Count
                    ? null
                    : permissionIds.Select(permissionId => RolePermission.Create(roleGuid, permissionId)).ToList();
            },
            cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SecurityModule>> GetActiveCatalogAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        // Same rule as DbSecurityStore: a plan names modules by id, so a row counts only when its code belongs to its id.
        var ids = (await DbSecurityStore.PlanModulesAsync(_securityDb, tenantId, cancellationToken)).Select(module => module.Id).ToList();

        if (ids.Count == 0)
        {
            return [];
        }

        var modules = await _securityDb.Modules
            .Where(module => module.IsActive && ids.Contains(module.Id))
            .OrderBy(module => module.DisplayOrder)
            .ToListAsync(cancellationToken);
        var moduleIds = modules.Select(module => module.Id).ToList();
        var permissions = await _securityDb.Permissions
            .Where(permission => permission.IsActive && moduleIds.Contains(permission.ModuleId))
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

        return await _securityDb.UserModulePermissions
            .Where(row => row.UserId == userGuid)
            .Select(row => new UserPermissionOverride(row.Permission.Code, row.AccessType))
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// See <see cref="ReplaceRowsAsync{TParent, TRow}"/> for the transaction, locking and retry rules.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The context has pending changes, or its provider is not relational.
    /// </exception>
    public async Task<bool> ReplaceUserOverridesAsync(string userId, IEnumerable<UserPermissionOverride> overrides, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(userId, out var userGuid) || _securityDb is not DbContext dbContext)
        {
            return false;
        }

        var byCode = new Dictionary<string, PermissionAccessType>(StringComparer.Ordinal);
        foreach (var item in overrides ?? [])
        {
            // An empty code is invalid like any other: refusing it, instead of skipping it, keeps a Deny the caller meant
            // to write from being reported as written.
            if (item is null || !SecurityCodes.TryNormalize(item.Code, out var code))
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
                    : await _securityDb.Permissions.Where(permission => wanted.Contains(permission.Code)).ToListAsync(cancellationToken);
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
            },
            cancellationToken);
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
        Func<Task<IReadOnlyList<TRow>?>> createRows,
        CancellationToken cancellationToken)
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
            return await ReplaceRowsInCurrentTransactionAsync<TParent, TRow>(db, current, operation, parentId, ownedByParent, createRows, cancellationToken);
        }

        if (System.Transactions.Transaction.Current != null)
        {
            // The TransactionScope owns atomicity; an execution strategy cannot retry inside it.
            return await ReplaceRowsOnceAsync<TParent, TRow>(db, parentId, ownedByParent, createRows, cancellationToken);
        }

        var strategy = db.Database.CreateExecutionStrategy();
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await strategy.ExecuteAsync(async ct =>
                {
                    await using var transaction = await db.Database.BeginTransactionAsync(ct);
                    if (!await ReplaceRowsOnceAsync<TParent, TRow>(db, parentId, ownedByParent, createRows, ct))
                    {
                        await transaction.RollbackAsync(ct);
                        return false;
                    }

                    // The work is done: a cancelled commit would leave its outcome unknown.
                    await transaction.CommitAsync(CancellationToken.None);
                    return true;
                }, cancellationToken);
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
        Func<Task<IReadOnlyList<TRow>?>> createRows,
        CancellationToken cancellationToken)
        where TParent : class
        where TRow : class
    {
        return await SavepointScope.RunAsync(
            transaction,
            "pinotechrd_replace",
            operation,
            () => ReplaceRowsOnceAsync<TParent, TRow>(db, parentId, ownedByParent, createRows, cancellationToken),
            cancellationToken);
    }

    private static async Task<bool> ReplaceRowsOnceAsync<TParent, TRow>(
        DbContext db,
        Guid parentId,
        Expression<Func<TRow, bool>> ownedByParent,
        Func<Task<IReadOnlyList<TRow>?>> createRows,
        CancellationToken cancellationToken)
        where TParent : class
        where TRow : class
    {
        var locked = await db.Set<TParent>()
            .Where(parent => EF.Property<Guid>(parent, "Id") == parentId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(
                parent => EF.Property<string?>(parent, "ConcurrencyStamp"),
                parent => EF.Property<string?>(parent, "ConcurrencyStamp")), cancellationToken);
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

        await db.Set<TRow>().Where(ownedByParent).ExecuteDeleteAsync(cancellationToken);

        db.Set<TRow>().AddRange(rows);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
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
