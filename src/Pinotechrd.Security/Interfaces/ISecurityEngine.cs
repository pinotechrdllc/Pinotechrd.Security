using Pinotechrd.Security.Entities;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Defines the security engine logic for access validation.
/// </summary>
public interface ISecurityEngine
{
    /// <summary>
    /// Evaluates if the current user can access a specific feature.
    /// Hierarchy: Subscription -> Module -> Permission.
    /// </summary>
    Task<bool> CanAccessAsync(string moduleCode, string permissionName);

    /// <summary>
    /// Returns a recursively filtered menu tree based on the active security context.
    /// Optimization: This method should pre-fetch permissions to avoid N+1 queries.
    /// </summary>
    /// <param name="fullMenu">The complete menu structure to filter.</param>
    /// <returns>A filtered list of authorized menu items.</returns>
    Task<List<SecurityMenuItem>> GetAuthorizedMenuAsync(IEnumerable<SecurityMenuItem> fullMenu);

    /// <summary>
    /// Returns the complete set of permissions authorized for a user.
    /// This evaluates standard permissions but may be filtered by active modules.
    /// </summary>
    /// <remarks>Administrative: the caller must authorize acting on this user. For the authenticated user, use
    /// <see cref="GetCurrentUserPermissionsAsync"/>.</remarks>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <returns>A list of authorized permission codes.</returns>
    Task<IEnumerable<string>> GetPermissionsAsync(string userId);

    /// <summary>
    /// Returns the complete set of permissions authorized for the authenticated user of the request
    /// (<see cref="ISecurityDataProvider.GetCurrentUserId"/>), filtered like <see cref="GetPermissionsAsync"/>.
    /// </summary>
    /// <returns>A list of authorized permission codes; empty when there is no authenticated user, when
    /// <see cref="ISecurityDataProvider.GetCurrentTenantId"/> reports no tenant, or when that tenant is not the
    /// tenant of the request.</returns>
    Task<IEnumerable<string>> GetCurrentUserPermissionsAsync();
}
