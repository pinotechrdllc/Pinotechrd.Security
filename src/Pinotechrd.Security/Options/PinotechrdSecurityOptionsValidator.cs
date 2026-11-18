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

        if (string.IsNullOrWhiteSpace(settings.Issuer))
        {
            errors.Add("PinotechrdSecurityOptions.Jwt.Issuer is required.");
        }

        if (string.IsNullOrWhiteSpace(settings.Audience))
        {
            errors.Add("PinotechrdSecurityOptions.Jwt.Audience is required.");
        }

        return errors;
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
