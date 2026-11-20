using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace Pinotechrd.Security.Core;

/// <summary>
/// The user writes that end a session once it has started ending: renewing the security stamp and deleting the user.
/// They go to the user store with <see cref="CancellationToken.None"/>, because <see cref="UserManager{TUser}"/> in
/// ASP.NET Core passes the request's <c>RequestAborted</c> token to the store, so a client that disconnects between the
/// refresh-token revocation and this write would leave the stamp, and every token bound to it, in place.
/// </summary>
/// <remarks>
/// Without a user store (the managers were built by hand) or with a store that keeps no stamps, the
/// <see cref="UserManager{TUser}"/> methods are used as before. The stamp is a new random value, like Identity's; the
/// user validators do not run, since nothing they check changes.
/// </remarks>
internal static class UncancellableUserWrites
{
    public static async Task<IdentityResult> RenewSecurityStampAsync<TUser>(UserManager<TUser> userManager, IUserStore<TUser>? store, TUser user)
        where TUser : class
    {
        if (store is not IUserSecurityStampStore<TUser> stamps)
        {
            return await userManager.UpdateSecurityStampAsync(user);
        }

        await stamps.SetSecurityStampAsync(user, NewSecurityStamp(), CancellationToken.None);
        return await store.UpdateAsync(user, CancellationToken.None);
    }

    public static Task<IdentityResult> DeleteAsync<TUser>(UserManager<TUser> userManager, IUserStore<TUser>? store, TUser user)
        where TUser : class
        => store == null ? userManager.DeleteAsync(user) : store.DeleteAsync(user, CancellationToken.None);

    private static string NewSecurityStamp() => Convert.ToHexString(RandomNumberGenerator.GetBytes(20));
}
