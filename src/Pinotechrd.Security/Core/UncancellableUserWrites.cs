using System.Collections.Concurrent;
using System.Reflection;
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
/// <para>
/// The store is used only when the user manager does not override the method the write replaces
/// (<c>UpdateSecurityStampAsync</c> and the protected <c>UpdateUserAsync</c> for the stamp, <c>DeleteAsync</c> for the
/// deletion): a manager that customises them (soft delete, auditing) keeps being called, and must then make its own
/// writes independent of the request. So is the manager without a user store (built by hand) or with a store that keeps
/// no stamps.
/// </para>
/// <para>
/// The stamp renewal sets a new random stamp in Identity's format and normalises the user name and email first, as
/// <c>UserManager.UpdateUserAsync</c> does; the user validators do not run, so a stored user that no longer passes
/// them (for example a legacy duplicate email) can still have its sessions ended. Identity's update and delete metrics
/// are not recorded for these writes.
/// </para>
/// </remarks>
internal static class UncancellableUserWrites
{
    public static async Task<IdentityResult> RenewSecurityStampAsync<TUser>(UserManager<TUser> userManager, IUserStore<TUser>? store, TUser user)
        where TUser : class
    {
        if (store is not IUserSecurityStampStore<TUser> stamps || Overrides<TUser>.Stamp(userManager.GetType()))
        {
            return await userManager.UpdateSecurityStampAsync(user);
        }

        var none = CancellationToken.None;
        await stamps.SetSecurityStampAsync(user, NewSecurityStamp(), none);
        // As UserManager.UpdateUserAsync does, but without the manager's request-bound token.
        await store.SetNormalizedUserNameAsync(user, userManager.NormalizeName(await store.GetUserNameAsync(user, none)), none);
        if (store is IUserEmailStore<TUser> emails)
        {
            await emails.SetNormalizedEmailAsync(user, userManager.NormalizeEmail(await emails.GetEmailAsync(user, none)), none);
        }

        return await store.UpdateAsync(user, none);
    }

    public static Task<IdentityResult> DeleteAsync<TUser>(UserManager<TUser> userManager, IUserStore<TUser>? store, TUser user)
        where TUser : class
        => store == null || Overrides<TUser>.Delete(userManager.GetType())
            ? userManager.DeleteAsync(user)
            : store.DeleteAsync(user, CancellationToken.None);

    /// <summary>20 random bytes in RFC 4648 base32, 32 characters: the format of Identity's own stamps.</summary>
    internal static string NewSecurityStamp()
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = RandomNumberGenerator.GetBytes(20);
        var chars = new char[32];
        for (int bit = 0, i = 0; i < chars.Length; i++, bit += 5)
        {
            var index = bit / 8;
            var offset = bit % 8;
            var value = (bytes[index] << 8 | (index + 1 < bytes.Length ? bytes[index + 1] : 0)) >> (11 - offset) & 0x1F;
            chars[i] = alphabet[value];
        }

        return new string(chars);
    }

    /// <summary>Which user manager types override the methods these writes replace, cached per type.</summary>
    private static class Overrides<TUser>
        where TUser : class
    {
        private static readonly ConcurrentDictionary<Type, (bool Stamp, bool Delete)> s_cache = new();

        public static bool Stamp(Type managerType) => Of(managerType).Stamp;

        public static bool Delete(Type managerType) => Of(managerType).Delete;

        private static (bool Stamp, bool Delete) Of(Type managerType) => s_cache.GetOrAdd(managerType, type => (
            IsOverridden(type, nameof(UserManager<TUser>.UpdateSecurityStampAsync)) || IsOverridden(type, "UpdateUserAsync"),
            IsOverridden(type, nameof(UserManager<TUser>.DeleteAsync))));

        private static bool IsOverridden(Type type, string name)
        {
            var method = type.GetMethod(
                name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, [typeof(TUser)]);
            return method != null && method.DeclaringType != typeof(UserManager<TUser>);
        }
    }
}
