using System.Security.Cryptography;
using System.Text;

namespace Pinotechrd.Security.Core;

/// <summary>
/// The one place where module and permission codes are validated and normalised.
/// </summary>
/// <remarks>
/// A code is 1 to 100 characters from the ASCII alphabet <c>A-Z a-z 0-9 _ . -</c> after trimming. It is
/// normalised by trimming and upper-casing, so the stored form matches <c>[A-Z0-9_.-]+</c>. Characters outside
/// the alphabet are rejected rather than folded: <c>ToUpperInvariant</c> would otherwise turn, for example,
/// U+017F (long s) into <c>S</c> and let two different strings name one code.
/// </remarks>
internal static class SecurityCodes
{
    public const int MaxLength = 100;

    public static bool IsValid(string? code)
    {
        var trimmed = code?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > MaxLength) return false;

        foreach (var c in trimmed)
        {
            if (c is not ((>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '.' or '-'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Normalises a code; throws <see cref="ArgumentException"/> when it is not valid.</summary>
    public static string Normalize(string? code, string? paramName = null)
    {
        if (!IsValid(code))
        {
            throw new ArgumentException("A security code must be 1 to 100 characters from A-Z, a-z, 0-9, '_', '.' and '-'.", paramName ?? nameof(code));
        }

        return code!.Trim().ToUpperInvariant();
    }

    public static bool TryNormalize(string? code, out string normalized)
    {
        if (IsValid(code))
        {
            normalized = code!.Trim().ToUpperInvariant();
            return true;
        }

        normalized = string.Empty;
        return false;
    }
}

/// <summary>
/// Deterministic module identifiers, so the same module code has the same id in every tenant schema and a
/// plan in the shared catalog can name its modules by id.
/// </summary>
/// <remarks>
/// The id is a name-based UUID, version 5 (RFC 9562, section 5.5), of the normalised module code (trimmed,
/// upper case) in a fixed namespace. It never changes for a given code, and it equals PostgreSQL's
/// <c>uuid_generate_v5(Namespace, code)</c> from the <c>uuid-ossp</c> extension for the normalised code.
/// Modules created before this existed keep their random ids; see the changelog for how to align them.
/// </remarks>
public static class SecurityModuleId
{
    /// <summary>
    /// Namespace of the module ids. Fixed forever: changing it would change every id.
    /// </summary>
    public static readonly Guid Namespace = new("4f8a2c1e-9d3b-4e7a-8c5f-2b6d1a9e7c30");

    /// <summary>
    /// Returns the id of the module with <paramref name="code"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The code is empty or outside the code alphabet.</exception>
    public static Guid FromCode(string code)
    {
        var normalized = SecurityCodes.Normalize(code, nameof(code));

        var name = Encoding.UTF8.GetBytes(normalized);
        var input = new byte[16 + name.Length];
        Namespace.TryWriteBytes(input, bigEndian: true, out _);
        name.CopyTo(input, 16);

        // SHA-1 is what RFC 9562 prescribes for version 5; it is used here as an id derivation, not for security.
#pragma warning disable CA5350
        var hash = SHA1.HashData(input);
#pragma warning restore CA5350

        var bytes = hash.AsSpan(0, 16).ToArray();
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50); // version 5
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80); // RFC variant
        return new Guid(bytes, bigEndian: true);
    }

    /// <summary>
    /// Whether <paramref name="id"/> is the id of <paramref name="code"/>. A plan names its modules by id, so a module row
    /// counts for a plan only when its id and its code agree; a row whose code was changed after it was created, or one
    /// with a random id from before deterministic ids, does not. Never throws: an invalid code matches no id.
    /// </summary>
    internal static bool IsIdOf(Guid id, string? code) =>
        SecurityCodes.TryNormalize(code, out var normalized) && FromCode(normalized) == id;
}
