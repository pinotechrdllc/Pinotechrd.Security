using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;

namespace Pinotechrd.Security.Tests.Hosting;

public sealed record LoginRequest(string Email, string Password);

public sealed record RefreshRequest(string RefreshToken);

/// <summary>
/// The library's wiring (AddPinotechrdSecurity, tenant middleware, in-memory token stores) over a real relational
/// provider with one SQLite database file per tenant. SQLite has no schemas, so a database per tenant is what gives
/// each tenant its own tables; the context still builds a per-tenant model through UsePinotechrdSecurity().
/// </summary>
internal sealed class TenantDatabaseApi : IAsyncDisposable
{
    public const string Secret = "tenant-database-api-secret-key-with-32-plus-bytes";
    public const string Issuer = "tenant-db-api";
    public const string Audience = "tenant-db-api-clients";
    public const string Password = "Passw0rd!x";

    private readonly string _directory;

    private TenantDatabaseApi(InProcessHost host, string directory)
    {
        Host = host;
        _directory = directory;
    }

    public InProcessHost Host { get; }

    public HttpClient Client => Host.Client;

    public static async Task<TenantDatabaseApi> StartAsync(
        IReadOnlyDictionary<string, string[]> usersPerTenant,
        TenantSchemaMode mode = TenantSchemaMode.SchemaPerTenantInModel,
        Action<DbContextOptionsBuilder>? configureOptions = null,
        Action<DbContextOptionsBuilder, string>? useDatabase = null,
        bool provision = true,
        Action<WebApplicationBuilder>? configureBuilder = null,
        Action<WebApplication>? mapExtra = null,
        Action<PinotechrdSecurityOptions>? configureSecurity = null)
    {
        var directory = Path.Combine(Path.GetTempPath(), "pinotechrd-security-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        var host = await InProcessHost.StartAsync(
            builder =>
            {
                var services = builder.Services;
                services.AddProblemDetails();
                services.AddScoped<ISchemaProvider>(sp => new DbSchemaProvider(sp.GetRequiredService<TenantContext>()));
                services.AddDbContext<SecDb>((sp, options) =>
                {
                    var tenant = sp.GetRequiredService<TenantContext>().TenantId ?? "none";
                    if (useDatabase != null) useDatabase(options, tenant);
                    else options.UseSqlite($"Data Source={Path.Combine(directory, tenant + ".db")}");
                    options.UsePinotechrdSecurity(o => o.TenantSchemaMode = mode);
                    configureOptions?.Invoke(options);
                });
                services.AddPinotechrdSecurity<SecDb, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = Secret;
                    o.Jwt.Issuer = Issuer;
                    o.Jwt.Audience = Audience;
                    configureSecurity?.Invoke(o);
                });
                services.AddHostStubs(new FixedTenantStore(usersPerTenant.Keys.ToArray()));
                configureBuilder?.Invoke(builder);
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                app.UseAuthorization();

                app.MapPost("/api/auth/login", async (LoginRequest request, TenantContext tenant, IPinotechrdAuthManager<HostUser> auth) =>
                {
                    var result = await auth.LoginAsync(request.Email, request.Password, tenant.TenantId ?? string.Empty);
                    if (result.RequiresTwoFactor) return Results.Json(new { twoFactorToken = result.TwoFactorToken });
                    return result.Succeeded
                        ? Results.Json(new { access = result.Token!.AccessToken, refresh = result.Token.RefreshToken })
                        : Results.Json(new { error = result.ErrorMessage }, statusCode: 401);
                }).AllowAnonymous();

                app.MapPost("/api/auth/refresh", async (RefreshRequest request, IPinotechrdAuthManager<HostUser> auth) =>
                {
                    var result = await auth.RefreshAsync(request.RefreshToken);
                    return result.Succeeded
                        ? Results.Json(new { access = result.Token!.AccessToken, refresh = result.Token.RefreshToken })
                        : Results.Json(new { error = result.ErrorMessage }, statusCode: 401);
                }).AllowAnonymous();

                app.MapGet("/api/me", [Authorize] (HttpContext http, TenantContext tenant) => Results.Json(new
                {
                    tenant = tenant.TenantId,
                    claim = http.User.FindFirst("tenant_id")?.Value
                }));

                app.MapPost("/api/auth/logout", [Authorize] async (IPinotechrdAuthManager<HostUser> auth) =>
                {
                    await auth.SignOutCurrentUserAsync();
                    return Results.NoContent();
                });

                mapExtra?.Invoke(app);
            });

        var api = new TenantDatabaseApi(host, directory);
        foreach (var (tenant, emails) in usersPerTenant)
        {
            using var scope = host.Services.CreateScope();
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetTenant(tenant);
            if (provision)
            {
                var db = scope.ServiceProvider.GetRequiredService<SecDb>();
                await db.Database.EnsureCreatedAsync();
                await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL");
            }

            var users = scope.ServiceProvider.GetRequiredService<UserManager<HostUser>>();
            foreach (var email in emails)
            {
                var created = await users.CreateAsync(new HostUser { UserName = email, Email = email, EmailConfirmed = true }, Password);
                if (!created.Succeeded)
                {
                    throw new InvalidOperationException(string.Join(", ", created.Errors.Select(e => e.Description)));
                }
            }
        }

        return api;
    }

    /// <summary>Runs <paramref name="work"/> in a scope whose tenant is already resolved, like a request would.</summary>
    public async Task<T> InTenantAsync<T>(string tenant, Func<IServiceProvider, Task<T>> work)
    {
        using var scope = Host.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetTenant(tenant);
        return await work(scope.ServiceProvider);
    }

    public static string ExpiredAccessToken(string tenant, TimeSpan expiredFor)
    {
        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(Secret));
        var token = new JwtSecurityToken(
            Issuer,
            Audience,
            [new Claim("tenant_id", tenant), new Claim("sub", "user-1")],
            notBefore: DateTime.UtcNow - expiredFor - TimeSpan.FromMinutes(60),
            expires: DateTime.UtcNow - expiredFor,
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<HttpResponseMessage> PostAsync(string path, object body, string? tenant, string? bearer = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        if (tenant != null) request.Headers.Add("TenantId", tenant);
        if (bearer != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await Client.SendAsync(request);
    }

    public async Task<(string Access, string Refresh)> LoginAsync(string email, string tenant)
    {
        var response = await PostAsync("/api/auth/login", new LoginRequest(email, Password), tenant);
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (json.RootElement.GetProperty("access").GetString()!, json.RootElement.GetProperty("refresh").GetString()!);
    }

    /// <summary>Logs in a two-factor user over HTTP, like a client would, and returns the two-factor token.</summary>
    public async Task<string> LoginForTwoFactorTokenAsync(string email, string tenant)
    {
        var response = await PostAsync("/api/auth/login", new LoginRequest(email, Password), tenant);
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("twoFactorToken").GetString()!;
    }

    public async ValueTask DisposeAsync()
    {
        await Host.DisposeAsync();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
    }
}
