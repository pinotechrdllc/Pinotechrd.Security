using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Options;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Builds the HMAC-SHA256 keys of <see cref="JwtSettings"/>: <see cref="JwtSettings.Secret"/> signs and validates,
/// <see cref="JwtSettings.PreviousSecrets"/> only validate. Every key carries a <c>kid</c> derived from its secret.
/// </summary>
internal static class JwtSigningKeys
{
    /// <summary>
    /// The key id of a secret: the first 16 lowercase hex characters of SHA-256 over its UTF-8 bytes. It identifies
    /// the key without revealing the secret.
    /// </summary>
    public static string KeyId(string secret)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexStringLower(hash, 0, 8);
    }

    /// <summary>
    /// The symmetric key of a secret, with <see cref="SecurityKey.KeyId"/> set to <see cref="KeyId"/>.
    /// </summary>
    public static SymmetricSecurityKey CreateKey(string secret) =>
        new(Encoding.UTF8.GetBytes(secret)) { KeyId = KeyId(secret) };

    /// <summary>
    /// The credentials that sign new tokens: always the current <see cref="JwtSettings.Secret"/>.
    /// </summary>
    public static SigningCredentials CreateSigningCredentials(JwtSettings settings) =>
        new(CreateKey(settings.Secret), SecurityAlgorithms.HmacSha256);

    /// <summary>
    /// The keys accepted when validating a token: the current secret first, then each previous secret in order.
    /// </summary>
    public static IReadOnlyList<SecurityKey> ValidationKeys(JwtSettings settings)
    {
        var keys = new List<SecurityKey> { CreateKey(settings.Secret) };
        if (settings.PreviousSecrets is { } previous)
        {
            foreach (var secret in previous)
            {
                keys.Add(CreateKey(secret));
            }
        }

        return keys;
    }
}
