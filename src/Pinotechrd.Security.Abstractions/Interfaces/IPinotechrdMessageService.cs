using System.Threading.Tasks;
using Pinotechrd.Security.Enums;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Agnostic service for sending security-related messages (Email/SMS).
/// </summary>
public interface IPinotechrdMessageService
{
    /// <summary>
    /// Sends a security code to the specified destination.
    /// </summary>
    /// <param name="destination">Email or Phone number.</param>
    /// <param name="code">The generated code.</param>
    /// <param name="codeType">Type of flow (2FA, Reset, etc).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task representing the operation.</returns>
    Task SendCodeAsync(string destination, string code, SecurityCodeType codeType, CancellationToken cancellationToken = default);
}
