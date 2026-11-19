using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Extensions;

/// <summary>
/// Extension methods for registering the persistent (database) stores.
/// </summary>
public static class PersistentStoreExtensions
{
    /// <summary>
    /// Replaces the default <see cref="InMemoryRefreshTokenStore"/> with a scoped store that keeps refresh tokens in
    /// the tenant schema of <typeparamref name="TContext"/>, so tokens survive restarts and are shared by every instance.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Call it before or after <c>AddPinotechrdSecurity</c>; either order keeps this store. The context options must enable the tables with
    /// <c>UsePinotechrdSecurity(o =&gt; o.MapRefreshTokens = true)</c>, and the application must add and apply a migration
    /// to every tenant schema; otherwise every call of the store throws <see cref="InvalidOperationException"/>.
    /// </para>
    /// <para>
    /// The store shares the request's <typeparamref name="TContext"/> but does not use its change tracker, so it does
    /// not save the application's pending changes. Expiry is decided by the registered <see cref="TimeProvider"/>,
    /// or the system clock. A token of another tenant is not visible in this tenant's schema and is refused as not found.
    /// </para>
    /// </remarks>
    /// <typeparam name="TContext">Security DbContext registered by the application.</typeparam>
    /// <param name="services">Service collection to configure.</param>
    /// <returns>The same service collection for chaining.</returns>
    public static IServiceCollection AddPinotechrdEfRefreshTokenStore<TContext>(this IServiceCollection services)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        services.RemoveAll<IRefreshTokenStore>();
        services.AddScoped<IRefreshTokenStore, EfRefreshTokenStore<TContext>>();
        return services;
    }

    /// <summary>
    /// Replaces the default <see cref="InMemoryTwoFactorAttemptStore"/> with a scoped store that counts two-factor
    /// attempts in the tenant schema of <typeparamref name="TContext"/>, so a two-factor token allows the same few
    /// attempts in total across every instance and restart.
    /// </summary>
    /// <remarks>
    /// Call it before or after <c>AddPinotechrdSecurity</c>; either order keeps this store. The context options must
    /// enable the table with <c>UsePinotechrdSecurity(o =&gt; o.MapTwoFactorAttempts = true)</c>, and the application
    /// must add and apply a migration to every tenant schema; otherwise every call of the store throws
    /// <see cref="InvalidOperationException"/>. The store does not use the change tracker of the shared context.
    /// Two-factor tokens also need Data Protection keys shared by every instance (<c>PersistKeysTo*</c>).
    /// </remarks>
    /// <typeparam name="TContext">Security DbContext registered by the application.</typeparam>
    /// <param name="services">Service collection to configure.</param>
    /// <returns>The same service collection for chaining.</returns>
    public static IServiceCollection AddPinotechrdEfTwoFactorAttemptStore<TContext>(this IServiceCollection services)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        services.RemoveAll<ITwoFactorAttemptStore>();
        services.AddScoped<ITwoFactorAttemptStore, EfTwoFactorAttemptStore<TContext>>();
        return services;
    }
}
