namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Defines a provider for retrieving user-specific security data.
/// </summary>
public interface ISecurityDataProvider
{
    /// <summary>
    /// Gets the unique identifier of the current user.
    /// </summary>
    string? GetCurrentUserId();

    /// <summary>
    /// Gets the unique identifier of the current tenant.
    /// </summary>
    string? GetCurrentTenantId();

    /// <summary>
    /// Gets the names of the roles assigned to the specified user.
    /// </summary>
    Task<IEnumerable<string>> GetUserRolesAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the names of the permissions assigned to the specified user.
    /// </summary>
    Task<IEnumerable<string>> GetUserPermissionsAsync(string userId, CancellationToken cancellationToken = default);
}
