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
    /// <para>
    /// Also registers <see cref="IPinotechrdSessionPurger"/> (if none is registered), which deletes the expired rows of
    /// the current tenant; schedule it per tenant.
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
        RegisterPurger<TContext>(services, typeof(EfTwoFactorAttemptStore<>), typeof(ITwoFactorAttemptStore));
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
    /// Also registers <see cref="IPinotechrdSessionPurger"/> (if none is registered), which deletes the expired rows of
    /// the current tenant; schedule it per tenant.
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
        RegisterPurger<TContext>(services, typeof(EfRefreshTokenStore<>), typeof(IRefreshTokenStore));
        return services;
    }

    /// <summary>
    /// Registers the purger for <typeparamref name="TContext"/>, replacing a library purger registered for another
    /// context by an earlier call. Both EF stores must share one context, so one purger covers both tables; a
    /// mismatch throws. A purger registered by the application is kept.
    /// </summary>
    private static void RegisterPurger<TContext>(IServiceCollection services, Type otherStore, Type otherService)
        where TContext : DbContext
    {
        var other = services.LastOrDefault(d => d.ServiceType == otherService)?.ImplementationType;
        if (other is { IsGenericType: true }
            && other.GetGenericTypeDefinition() == otherStore
            && other.GetGenericArguments()[0] != typeof(TContext))
        {
            throw new InvalidOperationException(
                "The EF refresh token store and two-factor attempt store must use the same context, so one " +
                $"IPinotechrdSessionPurger purges both; got {other.GetGenericArguments()[0].Name} and {typeof(TContext).Name}.");
        }

        var existing = services.LastOrDefault(d => d.ServiceType == typeof(IPinotechrdSessionPurger))?.ImplementationType;
        if (existing is { IsGenericType: true } && existing.GetGenericTypeDefinition() == typeof(EfSessionPurger<>))
        {
            services.RemoveAll<IPinotechrdSessionPurger>();
        }

        services.TryAddScoped<IPinotechrdSessionPurger, EfSessionPurger<TContext>>();
    }
}
