using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Core;

/// <summary>
/// The <see cref="ISecurityDataProvider"/> that <c>AddPinotechrdSecurity</c> registers unless the application registers
/// its own: the user of the request's library access token, the resolved tenant, and the user's roles and permissions
/// from the tenant's own tables.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>The user id is an <c>id</c> claim issued by <see cref="JwtSettings.Issuer"/> on an authenticated identity of the
/// request, so an <c>id</c> claim from another authentication scheme or issuer never names a user. When the library's
/// bearer scheme validated the request's access token (and the application's own <c>OnTokenValidated</c> did not fail
/// it), the id must be that token's. When identities disagree, or outside a request, there is no user: an application
/// that signs users in with another scheme registers its own provider.</item>
/// <item>The tenant is <see cref="TenantContext"/>, which the tenant middleware resolves (the verified claim for an
/// authenticated user), never a header read here.</item>
/// <item>Roles and permissions are read through the request's context, so from the tenant's schema: the role names, and
/// the codes of the permissions assigned to those roles, for an active user only. User overrides are applied by the
/// engine, not here.</item>
/// </list>
/// </remarks>
internal sealed class DefaultSecurityDataProvider<TContext, TUser, TRole> : ISecurityDataProvider
    where TContext : DbContext
    where TUser : BaseSecurityUser
    where TRole : BaseSecurityRole
{
    private readonly IHttpContextAccessor _http;
    private readonly TenantContext _tenant;
    private readonly TContext _db;
    private readonly string? _issuer;

    public DefaultSecurityDataProvider(IHttpContextAccessor http, TenantContext tenant, TContext db, IOptions<PinotechrdSecurityOptions> options)
    {
        _http = http;
        _tenant = tenant;
        _db = db;
        _issuer = options.Value.Jwt.Issuer;
    }

    public string? GetCurrentUserId()
    {
        var context = _http.HttpContext;
        if (context == null || _issuer == null) return null;

        // Only the library's own tokens name a user: id claims issued by Jwt.Issuer on authenticated identities.
        var ids = context.User.Identities
            .Where(i => i.IsAuthenticated)
            .SelectMany(i => i.FindAll(c => c.Type == SecurityStampClaim.UserIdType && string.Equals(c.Issuer, _issuer, StringComparison.Ordinal)))
            .Select(c => c.Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (ids.Count != 1) return null;

        // When the bearer scheme validated a token on this request, the identity must be that token's user.
        if (ValidatedAccessToken.Read(context) is { } token
            && (token.UserIds.Count != 1 || !string.Equals(token.UserIds[0], ids[0], StringComparison.Ordinal)))
        {
            return null;
        }

        return ids[0];
    }

    public string? GetCurrentTenantId() => _tenant.TenantId;

    public async Task<IEnumerable<string>> GetUserRolesAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(userId, out var id)) return [];
        return await (from userRole in _db.Set<IdentityUserRole<Guid>>()
                      join user in _db.Set<TUser>() on userRole.UserId equals user.Id
                      join role in _db.Set<TRole>() on userRole.RoleId equals role.Id
                      where userRole.UserId == id && user.IsActive && role.Name != null
                      select role.Name!)
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    }

    public async Task<IEnumerable<string>> GetUserPermissionsAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(userId, out var id)) return [];
        return await (from userRole in _db.Set<IdentityUserRole<Guid>>()
                      join user in _db.Set<TUser>() on userRole.UserId equals user.Id
                      join rolePermission in _db.Set<RolePermission>() on userRole.RoleId equals rolePermission.RoleId
                      where userRole.UserId == id && user.IsActive
                      select rolePermission.Permission.Code)
            .Distinct()
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    }
}
