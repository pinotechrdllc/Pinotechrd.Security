namespace Pinotechrd.Security.Enums;

/// <summary>
/// Status of a tenant in the system.
/// </summary>
public enum TenantStatus
{
    /// <summary>
    /// Tenant is being provisioned.
    /// </summary>
    Provisioning = 0,

    /// <summary>
    /// Tenant is active and operational.
    /// </summary>
    Active = 1,

    /// <summary>
    /// Tenant is temporarily suspended.
    /// </summary>
    Suspended = 2,

    /// <summary>
    /// Tenant is permanently cancelled.
    /// </summary>
    Cancelled = 3
}

/// <summary>
/// Type of access granted for a specific permission (Allow or Deny).
/// </summary>
public enum PermissionAccessType
{
    /// <summary>
    /// Explicitly allows access.
    /// </summary>
    Allow = 1,

    /// <summary>
    /// Explicitly denies access.
    /// </summary>
    Deny = 2
}

/// <summary>
/// Type of security code being sent (e.g., Two-Factor, Password Reset).
/// </summary>
public enum SecurityCodeType
{
    /// <summary>
    /// Code used for multi-factor authentication.
    /// </summary>
    TwoFactor = 1,

    /// <summary>
    /// Code used for password reset.
    /// </summary>
    PasswordReset = 2
}
