using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Provides a hook for domain-specific user validation after identity verification.
/// </summary>
/// <typeparam name="TUser">The type of the user being validated.</typeparam>
public interface IIdentityValidator<TUser> where TUser : class
{
    /// <summary>
    /// Performs additional business validation (e.g., checking if an employee is active).
    /// </summary>
    /// <param name="user">The validated identity user.</param>
    /// <param name="tenantId">The target tenant identifier.</param>
    /// <returns>A result indicating if the validation passed and optional extra claims.</returns>
    Task<IdentityValidationResult> ValidateAsync(TUser user, string tenantId);
}

/// <summary>
/// Represents the result of a custom identity validation.
/// </summary>
public record IdentityValidationResult(
    bool Succeeded,
    string? ErrorMessage = null,
    string? FullName = null,
    IEnumerable<Claim>? AdditionalClaims = null)
{
    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static IdentityValidationResult Success(string fullName, IEnumerable<Claim>? extraClaims = null) 
        => new(true, null, fullName, extraClaims);

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    public static IdentityValidationResult Failure(string errorMessage) 
        => new(false, errorMessage);
}
