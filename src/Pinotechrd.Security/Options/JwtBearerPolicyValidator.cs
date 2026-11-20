using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Core;

namespace Pinotechrd.Security.Options;

/// <summary>
/// Checks the final <see cref="JwtBearerOptions"/> of the library's bearer scheme against the policy that
/// <c>AddPinotechrdSecurity</c> applies, after every <c>Configure</c> and <c>PostConfigure</c> has run.
/// </summary>
/// <remarks>
/// <para>
/// The library sets the policy in a <c>PostConfigure</c> step, which a <c>PostConfigure</c> registered later can still
/// change. Options validation runs last, so this is where a weakened policy is caught: the options fail to build, which
/// fails the host at start (through <see cref="JwtBearerPolicyStartupCheck"/>) and every later read. The messages name
/// the members, never values. Members the policy does not cover (for example <c>NameClaimType</c>, <c>ValidTypes</c>)
/// stay the application's.
/// </para>
/// <para>
/// Scope: the options as configured. Code the application runs during authentication (event handlers that set a
/// result, edits to <c>context.Options</c> at run time), other authentication schemes, and replacing the options
/// infrastructure (<c>IOptionsFactory</c>, <c>IOptionsMonitorCache</c>) are outside it. When the options are reloaded
/// from configuration, a reload that breaks the policy makes every read fail, so requests fail rather than
/// authenticate with the weaker settings.
/// </para>
/// </remarks>
internal sealed class JwtBearerPolicyValidator : IValidateOptions<JwtBearerOptions>
{
    private readonly IOptions<PinotechrdSecurityOptions> _security;

    public JwtBearerPolicyValidator(IOptions<PinotechrdSecurityOptions> security)
    {
        _security = security;
    }

    public ValidateOptionsResult Validate(string? name, JwtBearerOptions options)
    {
        if (!string.Equals(name, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal))
        {
            return ValidateOptionsResult.Skip;
        }

        var parameters = options.TokenValidationParameters;
        if (parameters == null)
        {
            return Fail(["TokenValidationParameters is null"]);
        }

        JwtSettings settings;
        try
        {
            settings = _security.Value.Jwt;
        }
        catch (OptionsValidationException)
        {
            // Defensive: the library's PostConfigure reads the same options first and throws, so the bearer options
            // are never built while they are invalid, and IOptions caches a successful value. Their own validation
            // already fails the host and every read with the exact reason.
            return ValidateOptionsResult.Skip;
        }

        var errors = new List<string>();

        Require(errors, parameters.ValidateIssuer, "ValidateIssuer must be true");
        Require(errors, parameters.ValidateAudience, "ValidateAudience must be true");
        Require(errors, parameters.ValidateLifetime, "ValidateLifetime must be true");
        Require(errors, parameters.ValidateIssuerSigningKey, "ValidateIssuerSigningKey must be true");
        Require(errors, parameters.RequireSignedTokens, "RequireSignedTokens must be true");
        Require(errors, parameters.RequireExpirationTime, "RequireExpirationTime must be true");

        Require(errors, string.Equals(parameters.ValidIssuer, settings.Issuer, StringComparison.Ordinal),
            "ValidIssuer must be PinotechrdSecurityOptions.Jwt.Issuer");
        Require(errors, string.Equals(parameters.ValidAudience, settings.Audience, StringComparison.Ordinal),
            "ValidAudience must be PinotechrdSecurityOptions.Jwt.Audience");
        Require(errors, parameters.ValidIssuers is null || !parameters.ValidIssuers.Any(), "ValidIssuers must be empty");
        Require(errors, parameters.ValidAudiences is null || !parameters.ValidAudiences.Any(), "ValidAudiences must be empty");
        Require(errors, parameters.ValidAlgorithms is { } algorithms
                        && algorithms.Count() == 1
                        && algorithms.Single() == SecurityAlgorithms.HmacSha256,
            "ValidAlgorithms must be HS256 only");

        Require(errors, parameters.IssuerValidator == null, "IssuerValidator must be null");
        Require(errors, parameters.IssuerValidatorUsingConfiguration == null, "IssuerValidatorUsingConfiguration must be null");
        Require(errors, parameters.AudienceValidator == null, "AudienceValidator must be null");
        Require(errors, parameters.LifetimeValidator == null, "LifetimeValidator must be null");
        Require(errors, parameters.AlgorithmValidator == null, "AlgorithmValidator must be null");
        Require(errors, parameters.SignatureValidator == null, "SignatureValidator must be null");
        Require(errors, parameters.SignatureValidatorUsingConfiguration == null, "SignatureValidatorUsingConfiguration must be null");
        Require(errors, parameters.IssuerSigningKeyResolver == null, "IssuerSigningKeyResolver must be null");
        Require(errors, parameters.IssuerSigningKeyResolverUsingConfiguration == null, "IssuerSigningKeyResolverUsingConfiguration must be null");
        Require(errors, parameters.IssuerSigningKey == null, "IssuerSigningKey must be null");
        Require(errors, parameters.ConfigurationManager == null, "TokenValidationParameters.ConfigurationManager must be null");
        Require(errors, options.Configuration == null, "Configuration must be null");
        Require(errors, options.ConfigurationManager == null, "ConfigurationManager must be null");
        Require(errors, HasExactlyTheConfiguredKeys(parameters.IssuerSigningKeys, settings),
            "IssuerSigningKeys must be the keys of PinotechrdSecurityOptions.Jwt.Secret and PreviousSecrets");

        Require(errors, parameters.ClockSkew >= TimeSpan.Zero && parameters.ClockSkew <= settings.MaximumClockSkew,
            "ClockSkew must be between zero and PinotechrdSecurityOptions.Jwt.MaximumClockSkew");

        // Ways to run something other than this validation: a parameters subclass (the handler clones the parameters
        // on every request, and Clone is virtual), delegates that hand a different token to the signature check,
        // custom token handlers, and forwarding authentication to another scheme.
        Require(errors, parameters.GetType() == typeof(TokenValidationParameters),
            "TokenValidationParameters must be an instance of TokenValidationParameters itself, not a subclass");
        Require(errors, parameters.TokenReader == null, "TokenReader must be null");
        Require(errors, parameters.TransformBeforeSignatureValidation == null, "TransformBeforeSignatureValidation must be null");
        Require(errors, options.TokenHandlers.All(h => h.GetType() == typeof(JsonWebTokenHandler) || h.GetType() == typeof(JwtSecurityTokenHandler)),
            "TokenHandlers must hold only JsonWebTokenHandler or JwtSecurityTokenHandler instances");
#pragma warning disable CS0618 // SecurityTokenValidators is obsolete, but still used when UseSecurityTokenValidators is on.
        Require(errors, !options.UseSecurityTokenValidators
                        || options.SecurityTokenValidators.All(v => v.GetType() == typeof(JwtSecurityTokenHandler)),
            "SecurityTokenValidators must hold only JwtSecurityTokenHandler instances");
#pragma warning restore CS0618
        Require(errors, options.ForwardDefault == null, "ForwardDefault must be null");
        Require(errors, options.ForwardAuthenticate == null, "ForwardAuthenticate must be null");
        Require(errors, options.ForwardDefaultSelector == null, "ForwardDefaultSelector must be null");

        return errors.Count == 0 ? ValidateOptionsResult.Success : Fail(errors);
    }

    private static bool HasExactlyTheConfiguredKeys(IEnumerable<SecurityKey>? actual, JwtSettings settings)
    {
        if (actual == null) return false;
        var expected = JwtSigningKeys.ValidationKeys(settings);
        var keys = actual.ToList();
        if (keys.Count != expected.Count) return false;

        for (var i = 0; i < keys.Count; i++)
        {
            if (keys[i] is not SymmetricSecurityKey key
                || expected[i] is not SymmetricSecurityKey wanted
                || !key.Key.AsSpan().SequenceEqual(wanted.Key))
            {
                return false;
            }
        }

        return true;
    }

    private static void Require(List<string> errors, bool condition, string message)
    {
        if (!condition) errors.Add(message);
    }

    private static ValidateOptionsResult Fail(IEnumerable<string> errors) =>
        ValidateOptionsResult.Fail(errors.Select(e =>
            $"JwtBearerOptions '{JwtBearerDefaults.AuthenticationScheme}': {e}. AddPinotechrdSecurity enforces this validation policy; " +
            "a PostConfigure registered after it, or code that edits the options later, must not change it."));
}

/// <summary>
/// Builds the library's bearer options when the host starts, so <see cref="JwtBearerPolicyValidator"/> fails the start
/// instead of the first authenticated request.
/// </summary>
/// <remarks>
/// A hosted service rather than <c>ValidateOnStart</c>: hosted services start after the options marked
/// <c>ValidateOnStart</c> are validated, so invalid <see cref="PinotechrdSecurityOptions"/> fail the start with their own
/// single error before the bearer options (whose setup reads them) are built.
/// </remarks>
internal sealed class JwtBearerPolicyStartupCheck : IHostedService
{
    private readonly IOptionsMonitor<JwtBearerOptions> _options;

    public JwtBearerPolicyStartupCheck(IOptionsMonitor<JwtBearerOptions> options)
    {
        _options = options;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _ = _options.Get(JwtBearerDefaults.AuthenticationScheme);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
