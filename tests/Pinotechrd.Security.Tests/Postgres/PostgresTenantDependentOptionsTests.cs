using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// The README's registration for one database role per tenant (scoped options built from the request's tenant, refusing
/// without one) on PostgreSQL: the host starts, and the membership check runs at sign-in instead.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresTenantDependentOptionsTests(PostgresFixture postgres)
{
    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static IHost Build(string connectionString, TenantSchemaMode mode, bool provesMembership)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AllowEphemeralSecurityState();
        builder.Services.AddScoped<ISchemaProvider>(sp => new DbSchemaProvider(sp.GetRequiredService<TenantContext>()));
        builder.Services.AddDbContext<SecDb>((sp, options) =>
        {
            var tenant = sp.GetRequiredService<TenantContext>().TenantId
                ?? throw new InvalidOperationException("No tenant is resolved.");
            options.UseNpgsql(connectionString + ";Application Name=role-" + tenant); // stands for the tenant role's login
            options.UsePinotechrdSecurity(m =>
            {
                m.TenantSchemaMode = provesMembership ? mode : TenantSchemaMode.SearchPath;
                m.ApplicationTakesResponsibilityForSearchPath = !provesMembership;
            });
        }, contextLifetime: ServiceLifetime.Scoped, optionsLifetime: ServiceLifetime.Scoped);
        builder.Services.AddPinotechrdSecurity<SecDb, HostUser, HostRole>(o =>
        {
            o.Jwt.Secret = "tenant-dependent-options-secret-32-bytes!!";
            o.Jwt.Issuer = "iss";
            o.Jwt.Audience = "aud";
        });
        builder.Services.AddHostStubs();
        return builder.Build();
    }

    private static async Task<Pinotechrd.Security.Models.AuthResult> SignInAsync(IHost host, string cs, TenantSchemaMode mode)
    {
        using var scope = host.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetTenant("a");
        // The user is created through a context of the provisioning kind, so the check under test is only the sign-in's.
        await using (var owner = PgProvisioning.NewContext(cs, mode, "a"))
        {
            var users = new UserStore<HostUser, HostRole, SecDb, Guid>(owner);
            var user = new HostUser { UserName = "u@a.test", NormalizedUserName = "U@A.TEST", Email = "u@a.test", NormalizedEmail = "U@A.TEST", SecurityStamp = Guid.NewGuid().ToString("N") };
            user.PasswordHash = new PasswordHasher<HostUser>().HashPassword(user, "Passw0rd!x");
            await users.CreateAsync(user);
        }

        return await scope.ServiceProvider.GetRequiredService<IPinotechrdAuthManager<HostUser>>().LoginAsync("u@a.test", "Passw0rd!x", "a");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task TheReadmesPerTenantRegistration_ShouldStart_AndSignIn(TenantSchemaMode mode)
    {
        var cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(cs, mode, "a");
        using var host = Build(cs, mode, provesMembership: true);

        await host.StartAsync();
        try
        {
            (await SignInAsync(host, cs, mode)).Succeeded.Should().BeTrue();
        }
        finally
        {
            await host.StopAsync();
            Npgsql.NpgsqlConnection.ClearAllPools();
        }
    }

    [Fact]
    public async Task ATenantDependentRegistrationThatDoesNotProveMembership_ShouldStart_ButRefuseToSignIn()
    {
        var cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(cs, TenantSchemaMode.SearchPath, "a");
        using var host = Build(cs, TenantSchemaMode.SearchPath, provesMembership: false);

        await host.StartAsync();
        try
        {
            var act = () => SignInAsync(host, cs, TenantSchemaMode.SearchPath);
            (await act.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("ApplicationTakesResponsibilityForSearchPath");
        }
        finally
        {
            await host.StopAsync();
            Npgsql.NpgsqlConnection.ClearAllPools();
        }
    }
}
