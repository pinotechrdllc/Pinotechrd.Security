using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Provides administrative management operations for users and roles.
/// Encapsulates Identity infrastructure to prevent leakage into application business logic.
/// </summary>
/// <typeparam name="TUser">The identity user type.</typeparam>
/// <typeparam name="TRole">The identity role type.</typeparam>
public interface IPinotechrdSecurityManager<TUser, TRole> 
    where TUser : class 
    where TRole : class
{
    /// <summary>
    /// Returns all registered users.
    /// </summary>
    Task<IEnumerable<TUser>> GetUsersAsync();

    /// <summary>
    /// Gets a user by unique identifier.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user.</remarks>
    Task<TUser?> GetUserByIdAsync(string userId);

    /// <summary>
    /// Gets a user by email address.
    /// </summary>
    Task<TUser?> GetUserByEmailAsync(string email);

    /// <summary>
    /// Creates a user and optionally assigns roles.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every role in <paramref name="roles"/> must exist, and no name may be empty; otherwise no user is created and
    /// the method returns <c>false</c>. Repeated names are assigned once. If creating the user or assigning a role
    /// fails, the method returns <c>false</c>; exceptions from the store propagate.
    /// </para>
    /// <para>
    /// The user and its roles are written atomically on a relational EF Core provider: in a transaction of their own
    /// (run through the context's execution strategy), or, when the context already has a transaction, behind a
    /// savepoint inside it, where the caller keeps the commit. They are not atomic on a non-relational provider, or in
    /// a caller transaction on a provider without savepoints. Inside a <c>TransactionScope</c> they are rolled back
    /// only if the caller abandons the scope.
    /// </para>
    /// <para>
    /// On a relational provider the context must have no pending changes, or the method throws
    /// <see cref="System.InvalidOperationException"/>: the Identity store saves every pending change of the context,
    /// and a rollback would lose them.
    /// </para>
    /// </remarks>
    /// <returns><c>true</c> when the user was created with the requested roles; otherwise <c>false</c>.</returns>
    Task<bool> CreateUserAsync(TUser user, string password, IEnumerable<string>? roles = null);

    /// <summary>
    /// Persists updates for an existing user.
    /// </summary>
    Task<bool> UpdateUserAsync(TUser user);

    /// <summary>
    /// Deletes a user by identifier.
    /// </summary>
    /// <remarks>
    /// <para>Administrative: the caller must authorize acting on this user.</para>
    /// <para>
    /// The user's refresh tokens are revoked first. An exception from the refresh token store propagates and the
    /// user is not deleted; a failed delete returns <c>false</c> with the tokens already revoked.
    /// </para>
    /// </remarks>
    Task<bool> DeleteUserAsync(string userId);

    /// <summary>
    /// Enables or disables a user account.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user.</remarks>
    Task<bool> SetUserActiveStatusAsync(string userId, bool isActive);

    /// <summary>
    /// Signs a user out of every session: revokes all of its refresh tokens and renews its security stamp.
    /// Access tokens already issued stay valid until they expire.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user.</remarks>
    /// <returns><see langword="false"/>, with nothing changed, when the user is not found or no refresh token store is
    /// registered; <see langword="false"/>, with the tokens already revoked, when renewing the stamp fails; otherwise
    /// <see langword="true"/>.</returns>
    Task<bool> RevokeUserSessionsAsync(string userId);

    /// <summary>
    /// Resets the user password without requiring the current password.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user.</remarks>
    Task<bool> ResetUserPasswordAsync(string userId, string newPassword);

    /// <summary>
    /// Changes the user password using current password validation.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user.</remarks>
    Task<bool> ChangeUserPasswordAsync(string userId, string currentPassword, string newPassword);

    /// <summary>
    /// Returns all registered roles.
    /// </summary>
    Task<IEnumerable<TRole>> GetRolesAsync();

    /// <summary>
    /// Gets a role by unique identifier.
    /// </summary>
    Task<TRole?> GetRoleByIdAsync(string roleId);

    /// <summary>
    /// Gets a role by its display name.
    /// </summary>
    Task<TRole?> GetRoleByNameAsync(string roleName);

    /// <summary>
    /// Creates a role with an optional description.
    /// </summary>
    Task<bool> CreateRoleAsync(TRole role, string? description = null);

    /// <summary>
    /// Persists updates for an existing role.
    /// </summary>
    Task<bool> UpdateRoleAsync(TRole role);

    /// <summary>
    /// Deletes a role by identifier.
    /// </summary>
    Task<bool> DeleteRoleAsync(string roleId);

    /// <summary>
    /// Returns the role names currently assigned to the user.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user.</remarks>
    Task<IEnumerable<string>> GetUserRolesAsync(string userId);

    /// <summary>
    /// Assigns one or more roles to a user.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user.</remarks>
    Task<bool> AssignRolesToUserAsync(string userId, IEnumerable<string> roleNames);

    /// <summary>
    /// Removes one or more roles from a user.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user.</remarks>
    Task<bool> RemoveRolesFromUserAsync(string userId, IEnumerable<string> roleNames);

    /// <summary>
    /// Gets all available security permissions defined in the system.
    /// </summary>
    Task<IEnumerable<Pinotechrd.Security.Entities.SecurityPermission>> GetPermissionsAsync();

    /// <summary>
    /// Gets the permission codes assigned to a specific role.
    /// </summary>
    Task<IEnumerable<string>> GetRolePermissionsAsync(string roleId);

    /// <summary>
    /// Replaces the permissions assigned to a role with <paramref name="permissionCodes"/>. An empty list clears them.
    /// </summary>
    /// <remarks>
    /// The replace is atomic: a failure leaves the previous assignments intact. Concurrent replaces for the same role
    /// run one after the other, so the final assignments are exactly one of the requested sets. Outside a transaction, a
    /// <c>DbUpdateException</c> from saving the new rows is retried up to five times; any other error, and the last
    /// <c>DbUpdateException</c>, propagates. Inside a transaction the caller opened, the replace runs once behind a
    /// savepoint and is not retried. The role row receives a no-op <c>UPDATE</c> that serializes the replaces, so
    /// <c>UPDATE</c> triggers on it fire and a row version (<c>xmin</c>, <c>rowversion</c>) changes.
    /// See the README for the details.
    /// </remarks>
    /// <exception cref="System.InvalidOperationException">
    /// The context has pending changes (save or discard them first), or its provider is not relational.
    /// </exception>
    /// <returns>
    /// <see langword="false"/>, with nothing changed, when the role id is not a guid, the role does not exist, or a
    /// code is invalid or names a permission that does not exist.
    /// </returns>
    Task<bool> AssignPermissionsToRoleAsync(string roleId, IEnumerable<string> permissionCodes);

    /// <summary>
    /// Returns the modules on the tenant's active plan, each with its active permissions.
    /// A module that the plan does not include is absent.
    /// </summary>
    Task<IReadOnlyList<Pinotechrd.Security.Entities.SecurityModule>> GetActiveCatalogAsync(string tenantId);

    /// <summary>
    /// Returns the Allow and Deny overrides written for one user.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user.</remarks>
    Task<IReadOnlyList<Pinotechrd.Security.Models.UserPermissionOverride>> GetUserOverridesAsync(string userId);

    /// <summary>
    /// Replaces the user's Allow and Deny overrides. An empty list clears them.
    /// </summary>
    /// <remarks>
    /// <para>Administrative: the caller must authorize acting on this user.</para>
    /// <para>
    /// The replace is atomic: a failure leaves the previous overrides intact. Concurrent replaces for the same user
    /// run one after the other, so the final overrides are exactly one of the requested sets. Outside a transaction, a
    /// <c>DbUpdateException</c> from saving the new rows is retried up to five times; any other error, and the last
    /// <c>DbUpdateException</c>, propagates. Inside a transaction the caller opened, the replace runs once behind a
    /// savepoint and is not retried. The user row receives a no-op <c>UPDATE</c> that serializes the replaces, so
    /// <c>UPDATE</c> triggers on it fire and a row version (<c>xmin</c>, <c>rowversion</c>) changes.
    /// See the README for the details.
    /// </para>
    /// </remarks>
    /// <exception cref="System.InvalidOperationException">
    /// The context has pending changes (save or discard them first), or its provider is not relational.
    /// </exception>
    /// <returns>
    /// <see langword="false"/>, with nothing changed, when the user id is not a guid, the user does not exist, or a
    /// code is invalid or names a permission that does not exist.
    /// </returns>
    Task<bool> ReplaceUserOverridesAsync(string userId, IEnumerable<Pinotechrd.Security.Models.UserPermissionOverride> overrides);
}
