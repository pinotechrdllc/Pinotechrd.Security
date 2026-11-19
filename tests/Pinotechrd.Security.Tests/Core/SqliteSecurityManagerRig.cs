using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Pinotechrd.Security.Entities;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>
/// A security manager over a relational provider (SQLite) with one role, one user and three permissions, for tests of
/// the replace operations. <see cref="Fault"/> can make <c>SaveChanges</c> fail on demand.
/// </summary>
internal sealed class SqliteSecurityManagerRig : IAsyncDisposable
{
    private SqliteConnection _connection = null!;
    private ServiceProvider _provider = null!;
    private IServiceScope _scope = null!;

    public SecDb Db { get; private set; } = null!;
    public PinotechrdSecurityManager<HostUser, HostRole> Manager { get; private set; } = null!;
    public Guid RoleId { get; private set; }
    public Guid UserId { get; private set; }
    public SaveFault Fault { get; } = new();
    public PermissionDeleter DeleteAfterLock { get; } = new();

    public static async Task<SqliteSecurityManagerRig> CreateAsync()
    {
        var rig = new SqliteSecurityManagerRig();
        await rig.InitializeAsync();
        return rig;
    }

    private async Task InitializeAsync()
    {
        _connection = SecDbFactory.OpenMemory();
        var services = new ServiceCollection();
        services.AddLogging();
        var tenant = new TenantContext();
        tenant.SetTenant("a");
        services.AddSingleton(tenant);
        services.AddScoped<ISchemaProvider>(sp => new DbSchemaProvider(sp.GetRequiredService<TenantContext>()));
        services.AddDbContext<SecDb>(o =>
        {
            o.UseSqlite(_connection);
            o.UsePinotechrdSecurity();
            o.AddInterceptors(Fault, DeleteAfterLock);
        });
        services.AddIdentityCore<HostUser>().AddRoles<HostRole>().AddEntityFrameworkStores<SecDb>();
        _provider = services.BuildServiceProvider();
        _scope = _provider.CreateScope();
        Db = _scope.ServiceProvider.GetRequiredService<SecDb>();
        await Db.Database.EnsureCreatedAsync();

        await new SecuritySeeder(Db).SeedModuleAsync("Sales", "sales", null, 1,
        [
            ("View", "SALES.VIEW", null),
            ("Edit", "SALES.EDIT", null),
            ("Delete", "SALES.DELETE", null)
        ]);

        var roles = _scope.ServiceProvider.GetRequiredService<RoleManager<HostRole>>();
        var users = _scope.ServiceProvider.GetRequiredService<UserManager<HostUser>>();
        var role = new HostRole { Name = "clerk" };
        (await roles.CreateAsync(role)).Succeeded.Should().BeTrue();
        RoleId = role.Id;
        var user = new HostUser { UserName = "carol@a.test", Email = "carol@a.test" };
        (await users.CreateAsync(user)).Succeeded.Should().BeTrue();
        UserId = user.Id;
        DeleteAfterLock.Db = Db;
        Manager = new PinotechrdSecurityManager<HostUser, HostRole>(users, roles, Db);
    }

    public async Task<string[]> RoleCodesAsync()
    {
        Db.ChangeTracker.Clear();
        return (await Db.RolePermissions.Where(rp => rp.RoleId == RoleId).Select(rp => rp.Permission.Code).ToListAsync())
            .OrderBy(c => c, StringComparer.Ordinal).ToArray();
    }

    public async Task<string[]> UserOverridesAsync()
    {
        Db.ChangeTracker.Clear();
        var rows = await Db.UserModulePermissions.Where(r => r.UserId == UserId)
            .Select(r => new { r.Permission.Code, r.AccessType }).ToListAsync();
        return rows.Select(r => r.Code + ":" + r.AccessType).OrderBy(c => c, StringComparer.Ordinal).ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        _scope.Dispose();
        await _provider.DisposeAsync();
        await _connection.DisposeAsync();
    }

    /// <summary>Throws from <c>SaveChanges</c> while armed: <see cref="Remaining"/> more times.</summary>
    internal sealed class SaveFault : SaveChangesInterceptor
    {
        public int Remaining { get; set; }
        public int Calls { get; private set; }
        public Func<Exception> Make { get; set; } = () => new InvalidOperationException("boom");

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Calls++;
            if (Remaining > 0)
            {
                Remaining--;
                throw Make();
            }

            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }

    /// <summary>
    /// After the first UPDATE command runs (the manager's lock on the role or user row), deletes the permission with
    /// <see cref="Code"/> inside the same transaction: a permission removed after the request was validated.
    /// </summary>
    internal sealed class PermissionDeleter : DbCommandInterceptor
    {
        public string? Code { get; set; }
        public SecDb? Db { get; set; }

        public override async ValueTask<int> NonQueryExecutedAsync(
            DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (Code != null && command.CommandText.TrimStart().StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase))
            {
                var code = Code;
                Code = null;
                var table = Db!.Model.FindEntityType(typeof(SecurityPermission))!.GetTableName();
                await using var delete = command.Connection!.CreateCommand();
                delete.Transaction = command.Transaction;
                delete.CommandText = $"DELETE FROM \"{table}\" WHERE \"Code\" = '{code}'";
                await delete.ExecuteNonQueryAsync(cancellationToken);
            }

            return result;
        }
    }
}
