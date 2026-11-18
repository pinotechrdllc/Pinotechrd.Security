using Pinotechrd.Security.Enums;

namespace Pinotechrd.Security.Models;

/// <summary>
/// One permission a user is explicitly allowed or denied, on top of their roles.
/// The code is the full permission code stored for that permission.
/// </summary>
public sealed record UserPermissionOverride(string Code, PermissionAccessType Access);
