using System.Collections.Concurrent;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// <c>CreateUserAsync</c> is all-or-nothing on real PostgreSQL in both schema modes. Role assignment is made to fail by an
/// <see cref="IUserValidator{TUser}"/> that rejects (or throws on) the second validation of a marked user: the first
/// validation belongs to the user creation, the second to <c>AddToRolesAsync</c>, which updates the user.
/// One host per mode is shared by the tests of the class; each test uses its own users and roles.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresUserCreationTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string Tenant = "a";

    private readonly Dictionary<TenantSchemaMode, TenantDatabaseApi> _hosts = [];
    private readonly RoleFailureSwitch _switch = new();

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, "a", "b");
            _hosts[mode] = await TenantDatabaseApi.StartAsync(
                new Dictionary<string, string[]> { ["a"] = ["seed@a.test"], ["b"] = [] },
                mode,
                useDatabase: (options, _) => options.UseNpgsql(cs),
                provision: false,
                configureBuilder: builder =>
                {
                    builder.Services.AddSingleton(_switch);
                    builder.Services.AddScoped<IUserValidator<HostUser>, SwitchableUserValidator>();
                });
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var api in _hosts.Values) await api.DisposeAsync();
        Npgsql.NpgsqlConnection.ClearAllPools();
    }

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private TenantDatabaseApi Api(TenantSchemaMode mode) => _hosts[mode];

    private static string NewEmail() => "uc-" + Guid.NewGuid().ToString("N")[..8] + "@a.test";

    private static HostUser NewUser(string email) => new() { UserName = email, Email = email, EmailConfirmed = true };

    private static async Task<string> NewRoleAsync(TenantDatabaseApi api, string? name = null)
    {
        name ??= "role-" + Guid.NewGuid().ToString("N")[..8];
        await api.InTenantAsync(Tenant, async sp =>
        {
            (await sp.GetRequiredService<RoleManager<HostRole>>().CreateAsync(new HostRole { Name = name })).Succeeded.Should().BeTrue();
            return 0;
        });
        return name;
    }

    private static Task<bool> CreateAsync(TenantDatabaseApi api, string email, string password, params string[]? roles) =>
        api.InTenantAsync(Tenant, sp =>
            sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>().CreateUserAsync(NewUser(email), password, roles));

    /// <summary>The user and the number of user-role rows it has, read through a fresh scope.</summary>
    private static Task<(HostUser? User, IList<string> Roles, int UserRoleRows)> ReadAsync(TenantDatabaseApi api, string email) =>
        api.InTenantAsync(Tenant, async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            var user = await users.FindByEmailAsync(email);
            IList<string> roles = user == null ? [] : await users.GetRolesAsync(user);
            var rows = user == null ? 0 : await sp.GetRequiredService<SecDb>().UserRoles.CountAsync(r => r.UserId == user.Id);
            return (user, roles, rows);
        });

    private static Task<int> TotalUserRoleRowsAsync(TenantDatabaseApi api) =>
        api.InTenantAsync(Tenant, sp => sp.GetRequiredService<SecDb>().UserRoles.CountAsync());

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldCreateTheUserWithExactlyTheRequestedRoles(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var r1 = await NewRoleAsync(api);
        var r2 = await NewRoleAsync(api);
        var other = await NewRoleAsync(api);
        var email = NewEmail();

        (await CreateAsync(api, email, TenantDatabaseApi.Password, r1, r2)).Should().BeTrue();

        var (user, roles, rows) = await ReadAsync(api, email);
        user.Should().NotBeNull();
        roles.Should().BeEquivalentTo([r1, r2]).And.NotContain(other);
        rows.Should().Be(2);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldCreateTheUserWithoutRoles_WhenNoRolesAreRequested(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var withNull = NewEmail();
        var withEmpty = NewEmail();

        (await CreateAsync(api, withNull, TenantDatabaseApi.Password, null)).Should().BeTrue();
        (await CreateAsync(api, withEmpty, TenantDatabaseApi.Password)).Should().BeTrue();

        foreach (var email in new[] { withNull, withEmpty })
        {
            var (user, roles, rows) = await ReadAsync(api, email);
            user.Should().NotBeNull();
            roles.Should().BeEmpty();
            rows.Should().Be(0);
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldAssignOnce_WhenRoleNamesAreEqualAfterNormalization(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var name = await NewRoleAsync(api, "Mixed-" + Guid.NewGuid().ToString("N")[..6]);
        var email = NewEmail();

        (await CreateAsync(api, email, TenantDatabaseApi.Password, name, name.ToUpperInvariant(), name.ToLowerInvariant())).Should().BeTrue();

        var (user, roles, rows) = await ReadAsync(api, email);
        user.Should().NotBeNull();
        roles.Should().ContainSingle();
        rows.Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldReturnFalseAndCreateNoUser_WhenARoleDoesNotExist(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var known = await NewRoleAsync(api);
        var email = NewEmail();
        var rowsBefore = await TotalUserRoleRowsAsync(api);

        (await CreateAsync(api, email, TenantDatabaseApi.Password, known, "missing-" + Guid.NewGuid().ToString("N"))).Should().BeFalse();

        (await ReadAsync(api, email)).User.Should().BeNull();
        (await TotalUserRoleRowsAsync(api)).Should().Be(rowsBefore);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldNotFindARoleOfAnotherTenant(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var name = "only-b-" + Guid.NewGuid().ToString("N")[..8];
        await api.InTenantAsync("b", async sp =>
        {
            (await sp.GetRequiredService<RoleManager<HostRole>>().CreateAsync(new HostRole { Name = name })).Succeeded.Should().BeTrue();
            return 0;
        });
        var email = NewEmail();

        (await CreateAsync(api, email, TenantDatabaseApi.Password, name)).Should().BeFalse();

        (await ReadAsync(api, email)).User.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldReturnFalseAndCreateNoUser_WhenARoleNameIsBlank(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var known = await NewRoleAsync(api);

        foreach (var blank in new[] { "", "   " })
        {
            var email = NewEmail();

            (await CreateAsync(api, email, TenantDatabaseApi.Password, known, blank)).Should().BeFalse();

            (await ReadAsync(api, email)).User.Should().BeNull();
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldReturnFalseAndWriteNothing_WhenThePasswordIsWeak(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var email = NewEmail();
        var rowsBefore = await TotalUserRoleRowsAsync(api);

        (await CreateAsync(api, email, "abc", role)).Should().BeFalse();

        (await ReadAsync(api, email)).User.Should().BeNull();
        (await TotalUserRoleRowsAsync(api)).Should().Be(rowsBefore);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldReturnFalseAndKeepTheExistingUserUntouched_WhenTheEmailIsTaken(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var email = NewEmail();
        (await CreateAsync(api, email, TenantDatabaseApi.Password)).Should().BeTrue();
        var rowsBefore = await TotalUserRoleRowsAsync(api);

        (await CreateAsync(api, email, TenantDatabaseApi.Password, role)).Should().BeFalse();

        var (user, roles, _) = await ReadAsync(api, email);
        user.Should().NotBeNull();
        roles.Should().BeEmpty();
        (await TotalUserRoleRowsAsync(api)).Should().Be(rowsBefore);
        (await api.InTenantAsync(Tenant, sp => sp.GetRequiredService<SecDb>().Users.CountAsync(u => u.Email == email))).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldReturnFalseAndLeaveNoUserNorRoleRows_WhenRoleAssignmentFails(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var r1 = await NewRoleAsync(api);
        var r2 = await NewRoleAsync(api);
        var email = NewEmail();
        var rowsBefore = await TotalUserRoleRowsAsync(api);
        _switch.FailOnUpdate(email);

        var created = await CreateAsync(api, email, TenantDatabaseApi.Password, r1, r2);

        created.Should().BeFalse();
        _switch.UpdateCalls(email).Should().BeGreaterThan(0, "the failure must come from the role assignment step, not earlier");
        var (user, _, rows) = await ReadAsync(api, email);
        user.Should().BeNull();
        rows.Should().Be(0);
        (await TotalUserRoleRowsAsync(api)).Should().Be(rowsBefore);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldPropagateTheException_AndLeaveNothing_WhenTheStoreThrowsDuringRoleAssignment(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var email = NewEmail();
        var rowsBefore = await TotalUserRoleRowsAsync(api);
        _switch.ThrowOnUpdate(email);

        var act = () => CreateAsync(api, email, TenantDatabaseApi.Password, role);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*simulated store failure*");
        (await ReadAsync(api, email)).User.Should().BeNull();
        (await TotalUserRoleRowsAsync(api)).Should().Be(rowsBefore);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldAllowTheSameEmailToBeCreatedAfterAFailedAttempt(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var email = NewEmail();
        _switch.FailOnUpdate(email);
        (await CreateAsync(api, email, TenantDatabaseApi.Password, role)).Should().BeFalse();
        _switch.Clear(email);

        (await CreateAsync(api, email, TenantDatabaseApi.Password, role)).Should().BeTrue();

        var (user, roles, rows) = await ReadAsync(api, email);
        user.Should().NotBeNull();
        roles.Should().BeEquivalentTo([role]);
        rows.Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldNotTrackTheNewUserAnymore_WhenTheAttemptFails(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var failingRole = NewEmail();
        var failingPassword = NewEmail();
        _switch.FailOnUpdate(failingRole);

        await api.InTenantAsync(Tenant, async sp =>
        {
            var manager = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            var db = sp.GetRequiredService<SecDb>();

            (await manager.CreateUserAsync(NewUser(failingRole), TenantDatabaseApi.Password, [role])).Should().BeFalse();
            (await manager.CreateUserAsync(NewUser(failingPassword), "abc", [role])).Should().BeFalse();

            db.ChangeTracker.Entries<HostUser>().Should().NotContain(e => e.Entity.Email == failingRole || e.Entity.Email == failingPassword);
            await db.SaveChangesAsync();
            return 0;
        });

        (await ReadAsync(api, failingRole)).User.Should().BeNull();
        (await ReadAsync(api, failingPassword)).User.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldRollBackOnlyItsOwnWork_WhenTheCallerTransactionIsOpen(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var before = NewEmail();
        var failing = NewEmail();
        var after = NewEmail();
        _switch.FailOnUpdate(failing);

        await api.InTenantAsync(Tenant, async sp =>
        {
            var manager = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            var db = sp.GetRequiredService<SecDb>();
            await using var transaction = await db.Database.BeginTransactionAsync();

            (await manager.CreateUserAsync(NewUser(before), TenantDatabaseApi.Password, [role])).Should().BeTrue();
            (await manager.CreateUserAsync(NewUser(failing), TenantDatabaseApi.Password, [role])).Should().BeFalse();
            (await manager.CreateUserAsync(NewUser(after), TenantDatabaseApi.Password, [role])).Should().BeTrue();

            db.ChangeTracker.Entries<HostUser>().Should().NotContain(e => e.Entity.Email == failing);
            await db.SaveChangesAsync();
            await transaction.CommitAsync();
            return 0;
        });

        var kept = await ReadAsync(api, before);
        kept.User.Should().NotBeNull();
        kept.Roles.Should().BeEquivalentTo([role]);
        var later = await ReadAsync(api, after);
        later.User.Should().NotBeNull();
        later.Roles.Should().BeEquivalentTo([role]);
        var gone = await ReadAsync(api, failing);
        gone.User.Should().BeNull();
        gone.UserRoleRows.Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldLeaveTheCallerTransactionUsable_WhenTheStoreThrowsInsideIt(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var before = NewEmail();
        var throwing = NewEmail();
        var after = NewEmail();
        _switch.ThrowOnUpdate(throwing);

        await api.InTenantAsync(Tenant, async sp =>
        {
            var manager = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            var db = sp.GetRequiredService<SecDb>();
            await using var transaction = await db.Database.BeginTransactionAsync();

            (await manager.CreateUserAsync(NewUser(before), TenantDatabaseApi.Password, [role])).Should().BeTrue();
            var act = () => manager.CreateUserAsync(NewUser(throwing), TenantDatabaseApi.Password, [role]);
            await act.Should().ThrowAsync<InvalidOperationException>();
            (await manager.CreateUserAsync(NewUser(after), TenantDatabaseApi.Password, [role])).Should().BeTrue();

            await transaction.CommitAsync();
            return 0;
        });

        (await ReadAsync(api, before)).User.Should().NotBeNull();
        (await ReadAsync(api, after)).User.Should().NotBeNull();
        var gone = await ReadAsync(api, throwing);
        gone.User.Should().BeNull();
        gone.UserRoleRows.Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldThrowAndKeepThePendingEntity_WhenTheContextHasAnAddedEntityNotSaved(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var pendingName = "pending-" + Guid.NewGuid().ToString("N")[..8];
        var email = NewEmail();

        await api.InTenantAsync(Tenant, async sp =>
        {
            var manager = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            var db = sp.GetRequiredService<SecDb>();
            var pending = new HostRole { Name = pendingName, NormalizedName = pendingName.ToUpperInvariant() };
            db.Roles.Add(pending);

            var act = () => manager.CreateUserAsync(NewUser(email), TenantDatabaseApi.Password, [role]);

            await act.Should().ThrowAsync<InvalidOperationException>();
            db.Entry(pending).State.Should().Be(EntityState.Added, "the pending entity must not be lost or saved by the failed call");
            (await ReadAsync(api, email)).User.Should().BeNull();

            await db.SaveChangesAsync();
            (await manager.CreateUserAsync(NewUser(email), TenantDatabaseApi.Password, [role])).Should().BeTrue();
            return 0;
        });

        var (user, roles, _) = await ReadAsync(api, email);
        user.Should().NotBeNull();
        roles.Should().BeEquivalentTo([role]);
        (await api.InTenantAsync(Tenant, sp => sp.GetRequiredService<SecDb>().Roles.CountAsync(r => r.Name == pendingName))).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldThrowAndKeepTheModification_WhenATrackedEntityIsModifiedNotSaved(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var email = NewEmail();
        var description = "edited-" + Guid.NewGuid().ToString("N")[..6];

        await api.InTenantAsync(Tenant, async sp =>
        {
            var manager = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            var db = sp.GetRequiredService<SecDb>();
            var tracked = await db.Roles.SingleAsync(r => r.Name == role);
            tracked.Description = description;

            var act = () => manager.CreateUserAsync(NewUser(email), TenantDatabaseApi.Password, [role]);

            await act.Should().ThrowAsync<InvalidOperationException>();
            db.Entry(tracked).State.Should().Be(EntityState.Modified);
            (await ReadAsync(api, email)).User.Should().BeNull();

            await db.SaveChangesAsync();
            (await manager.CreateUserAsync(NewUser(email), TenantDatabaseApi.Password, [role])).Should().BeTrue();
            return 0;
        });

        (await ReadAsync(api, email)).User.Should().NotBeNull();
        (await api.InTenantAsync(Tenant, sp => sp.GetRequiredService<SecDb>().Roles.SingleAsync(r => r.Name == role))).Description.Should().Be(description);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldThrowAndWriteNothing_WhenTheContextHasPendingChangesInsideACallerTransaction(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var role = await NewRoleAsync(api);
        var pendingName = "pending-" + Guid.NewGuid().ToString("N")[..8];
        var email = NewEmail();

        await api.InTenantAsync(Tenant, async sp =>
        {
            var manager = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            var db = sp.GetRequiredService<SecDb>();
            await using var transaction = await db.Database.BeginTransactionAsync();
            var pending = new HostRole { Name = pendingName, NormalizedName = pendingName.ToUpperInvariant() };
            db.Roles.Add(pending);

            var act = () => manager.CreateUserAsync(NewUser(email), TenantDatabaseApi.Password, [role]);

            await act.Should().ThrowAsync<InvalidOperationException>();
            db.Entry(pending).State.Should().Be(EntityState.Added);
            await transaction.RollbackAsync();
            return 0;
        });

        (await ReadAsync(api, email)).User.Should().BeNull();
    }

    /// <summary>Per-test switch shared by the validator: which users fail or throw on their second validation.</summary>
    public sealed class RoleFailureSwitch
    {
        private readonly ConcurrentDictionary<string, string> _modes = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, int> _calls = new(StringComparer.OrdinalIgnoreCase);

        public void FailOnUpdate(string email) => _modes[email] = "fail";

        public void ThrowOnUpdate(string email) => _modes[email] = "throw";

        public void Clear(string email) => _modes.TryRemove(email, out _);

        public int UpdateCalls(string email) => _calls.TryGetValue(email, out var n) ? Math.Max(0, n - 1) : 0;

        internal string? Observe(string? email)
        {
            if (email == null || !_modes.TryGetValue(email, out var mode)) return null;
            var calls = _calls.AddOrUpdate(email, 1, (_, n) => n + 1);
            return calls >= 2 ? mode : null;
        }
    }

    private sealed class SwitchableUserValidator(RoleFailureSwitch failures) : IUserValidator<HostUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<HostUser> manager, HostUser user)
        {
            switch (failures.Observe(user.Email))
            {
                case "throw": throw new InvalidOperationException("simulated store failure");
                case "fail": return Task.FromResult(IdentityResult.Failed(new IdentityError { Code = "Simulated", Description = "simulated role assignment failure" }));
                default: return Task.FromResult(IdentityResult.Success);
            }
        }
    }
}
