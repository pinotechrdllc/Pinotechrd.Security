using System.Diagnostics.CodeAnalysis;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// The tenant identifier format accepted by the library, and its mapping to a database schema name.
/// </summary>
/// <remarks>
/// A tenant identifier is 1 to <see cref="MaxLength"/> characters from <c>a-z</c>, <c>0-9</c> and <c>-</c>,
/// and does not start with <c>-</c>. Lower-case GUIDs (<c>Guid.ToString()</c>) qualify. Upper case is rejected
/// rather than folded, so two spellings of one identifier can never reach the tenant store.
/// The schema name is <c>tenant_</c> followed by the identifier with <c>-</c> replaced by <c>_</c>. Because
/// <c>_</c> and upper case are not in the alphabet, two different identifiers never map to the same schema,
/// and the longest schema name is 63 characters, the PostgreSQL identifier limit.
/// </remarks>
public static class TenantIdentifier
{
    /// <summary>
    /// Maximum length of a tenant identifier.
    /// </summary>
    public const int MaxLength = 56;

    /// <summary>
    /// Prefix of every tenant schema name.
    /// </summary>
    public const string SchemaPrefix = "tenant_";

    /// <summary>
    /// Returns whether <paramref name="tenantId"/> is a well-formed tenant identifier.
    /// </summary>
    public static bool IsValid([NotNullWhen(true)] string? tenantId)
    {
        if (string.IsNullOrEmpty(tenantId) || tenantId.Length > MaxLength || tenantId[0] == '-')
        {
            return false;
        }

        foreach (var c in tenantId)
        {
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Maps a tenant identifier to its schema name. The mapping is injective.
    /// </summary>
    /// <exception cref="ArgumentException">The identifier is not well-formed.</exception>
    public static string ToSchemaName(string tenantId)
    {
        if (!IsValid(tenantId))
        {
            throw new ArgumentException("Tenant ID is not a valid tenant identifier.", nameof(tenantId));
        }

        return SchemaPrefix + tenantId.Replace('-', '_');
    }
}
