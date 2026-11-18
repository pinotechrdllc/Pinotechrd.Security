using System.Security.Claims;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Outcome of reading the tenant claim of a principal.
/// </summary>
internal enum TenantClaimStatus
{
    /// <summary>No identity of the principal is authenticated.</summary>
    NotAuthenticated,

    /// <summary>At least one identity is authenticated, but none carries the tenant claim.</summary>
    Missing,

    /// <summary>The authenticated identities carry exactly one tenant value.</summary>
    Single,

    /// <summary>The authenticated identities carry two or more different tenant values.</summary>
    Conflict
}

/// <summary>
/// Reads the tenant claim from the authenticated identities of a principal only. A claim on an
/// unauthenticated identity is never used.
/// </summary>
internal static class TenantClaims
{
    public static TenantClaimStatus Read(ClaimsPrincipal? principal, string claimType, out string? tenantId)
    {
        tenantId = null;
        var anyAuthenticated = false;

        foreach (var identity in principal?.Identities ?? [])
        {
            if (!identity.IsAuthenticated) continue;
            anyAuthenticated = true;

            foreach (var claim in identity.FindAll(claimType))
            {
                if (string.IsNullOrEmpty(claim.Value)) continue;
                if (tenantId == null)
                {
                    tenantId = claim.Value;
                }
                else if (!string.Equals(tenantId, claim.Value, StringComparison.Ordinal))
                {
                    tenantId = null;
                    return TenantClaimStatus.Conflict;
                }
            }
        }

        if (!anyAuthenticated) return TenantClaimStatus.NotAuthenticated;
        return tenantId == null ? TenantClaimStatus.Missing : TenantClaimStatus.Single;
    }
}
