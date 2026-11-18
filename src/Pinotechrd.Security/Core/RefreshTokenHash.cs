using System.Security.Cryptography;
using System.Text;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Hashes refresh token values, so that stores keep the SHA-256 of a token and never the token itself.
/// </summary>
internal static class RefreshTokenHash
{
    /// <summary>Length in bytes of a hash returned by <see cref="Compute"/>.</summary>
    public const int Length = 32;

    /// <summary>Returns the SHA-256 of the UTF-8 bytes of <paramref name="token"/>.</summary>
    public static byte[] Compute(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        return SHA256.HashData(Encoding.UTF8.GetBytes(token));
    }

    /// <summary>Returns <see cref="Compute"/> as an upper-case hexadecimal string.</summary>
    public static string ComputeHex(string token) => Convert.ToHexString(Compute(token));
}
