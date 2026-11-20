using System.Text;
using Microsoft.Extensions.Options;

namespace Pinotechrd.Security.Options;

/// <summary>
/// Validates <see cref="PinotechrdSecurityOptions"/> when the options are first used or, with
/// <c>ValidateOnStart</c>, when the host starts. Messages name the option path.
/// </summary>
internal sealed class PinotechrdSecurityOptionsValidator : IValidateOptions<PinotechrdSecurityOptions>
{
    public ValidateOptionsResult Validate(string? name, PinotechrdSecurityOptions options)
    {
        var errors = JwtSettingsRules.Validate(options.Jwt);
        if (options.TenantCacheExpiration <= TimeSpan.Zero)
        {
            errors.Add("PinotechrdSecurityOptions.TenantCacheExpiration must be positive.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}

/// <summary>
/// The rules a <see cref="JwtSettings"/> instance must meet.
/// </summary>
internal static class JwtSettingsRules
{
    /// <summary>
    /// Smallest accepted secret, in UTF-8 bytes (256 bits, the HMAC-SHA256 key size). Cannot be lowered.
    /// </summary>
    public const int MinimumSecretBytes = 32;

    public const int MinimumExpiryMinutes = 1;
    public const int MaximumExpiryMinutes = 60;
    public const int MinimumRefreshTokenExpiryDays = 1;
    public const int MaximumRefreshTokenExpiryDays = 90;

    /// <summary>
    /// Upper bound of <see cref="JwtSettings.MaximumClockSkew"/>: the framework default skew. A larger skew keeps
    /// expired tokens valid for longer, which defeats the lifetime check.
    /// </summary>
    public static readonly TimeSpan ClockSkewCeiling = TimeSpan.FromMinutes(5);

    /// <summary>Upper bound of <see cref="JwtSettings.SecurityStampValidationInterval"/>.</summary>
    public static readonly TimeSpan MaximumStampValidationInterval = TimeSpan.FromMinutes(5);

    public static int EffectiveMinimumBytes(JwtSettings settings) =>
        Math.Max(MinimumSecretBytes, settings.MinimumSecretLength);

    public static List<string> Validate(JwtSettings settings)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(settings.Secret))
        {
            errors.Add("PinotechrdSecurityOptions.Jwt.Secret is required. Set it from configuration or a secret store.");
        }
        else
        {
            var minimum = EffectiveMinimumBytes(settings);
            if (Encoding.UTF8.GetByteCount(settings.Secret) < minimum)
            {
                errors.Add($"PinotechrdSecurityOptions.Jwt.Secret must be at least {minimum} bytes in UTF-8.");
            }
        }

        ValidatePreviousSecrets(settings, errors);

        if (string.IsNullOrWhiteSpace(settings.Issuer))
        {
            errors.Add("PinotechrdSecurityOptions.Jwt.Issuer is required.");
        }

        if (string.IsNullOrWhiteSpace(settings.Audience))
        {
            errors.Add("PinotechrdSecurityOptions.Jwt.Audience is required.");
        }

        if (settings.ExpiryMinutes is < MinimumExpiryMinutes or > MaximumExpiryMinutes)
        {
            errors.Add($"PinotechrdSecurityOptions.Jwt.ExpiryMinutes must be between {MinimumExpiryMinutes} and {MaximumExpiryMinutes}.");
        }

        if (settings.RefreshTokenExpiryDays is < MinimumRefreshTokenExpiryDays or > MaximumRefreshTokenExpiryDays)
        {
            errors.Add($"PinotechrdSecurityOptions.Jwt.RefreshTokenExpiryDays must be between {MinimumRefreshTokenExpiryDays} and {MaximumRefreshTokenExpiryDays}.");
        }

        if (settings.MaximumClockSkew < TimeSpan.Zero || settings.MaximumClockSkew > ClockSkewCeiling)
        {
            errors.Add($"PinotechrdSecurityOptions.Jwt.MaximumClockSkew must be between zero and {ClockSkewCeiling.TotalMinutes:0} minutes.");
        }

        if (settings.SecurityStampValidationInterval < TimeSpan.Zero || settings.SecurityStampValidationInterval > MaximumStampValidationInterval)
        {
            errors.Add($"PinotechrdSecurityOptions.Jwt.SecurityStampValidationInterval must be between zero and {MaximumStampValidationInterval.TotalMinutes:0} minutes.");
        }

        return errors;
    }

    private static void ValidatePreviousSecrets(JwtSettings settings, List<string> errors)
    {
        if (settings.PreviousSecrets is not { } previous)
        {
            return;
        }

        var minimum = EffectiveMinimumBytes(settings);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < previous.Count; i++)
        {
            var secret = previous[i];
            var path = $"PinotechrdSecurityOptions.Jwt.PreviousSecrets[{i}]";
            if (string.IsNullOrWhiteSpace(secret))
            {
                errors.Add($"{path} must not be empty.");
                continue;
            }

            if (Encoding.UTF8.GetByteCount(secret) < minimum)
            {
                errors.Add($"{path} must be at least {minimum} bytes in UTF-8.");
            }

            if (string.Equals(secret, settings.Secret, StringComparison.Ordinal))
            {
                errors.Add($"{path} must not equal PinotechrdSecurityOptions.Jwt.Secret.");
            }
            else if (!seen.Add(secret))
            {
                errors.Add($"{path} duplicates an earlier entry of PinotechrdSecurityOptions.Jwt.PreviousSecrets.");
            }
        }
    }

    public static void ThrowIfInvalid(JwtSettings settings)
    {
        var errors = Validate(settings);
        if (errors.Count > 0)
        {
            throw new InvalidOperationException(string.Join(" ", errors));
        }
    }
}
