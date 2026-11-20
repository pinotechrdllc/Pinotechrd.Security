using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>Assigning permission codes to a role, on a relational provider.</summary>
public sealed class PinotechrdSecurityManagerPermissionsTests : IAsyncLifetime
{
    private SqliteConnection _connection = null!;
    private ServiceProvider _provider = null!;
    private IServiceScope _scope = null!;
    private SecDb _db = null!;
    private PinotechrdSecurityManager<HostUser, HostRole> _manager = null!;
    private Guid _roleId;

    public async Task InitializeAsync()
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
        });
        services.AddIdentityCore<HostUser>().AddRoles<HostRole>().AddEntityFrameworkStores<SecDb>();
        _provider = services.BuildServiceProvider();
        _scope = _provider.CreateScope();
        _db = _scope.ServiceProvider.GetRequiredService<SecDb>();
        await _db.Database.EnsureCreatedAsync();

        await new SecuritySeeder(_db).SeedModuleAsync("Sales", "sales", null, 1,
        [
            ("View", "SALES.VIEW", null),
            ("Edit", "SALES.EDIT", null),
            ("Delete", "SALES.DELETE", null)
        ]);

        var roles = _scope.ServiceProvider.GetRequiredService<RoleManager<HostRole>>();
        var role = new HostRole { Name = "clerk" };
        (await roles.CreateAsync(role)).Succeeded.Should().BeTrue();
        _roleId = role.Id;
        _manager = new PinotechrdSecurityManager<HostUser, HostRole>(
            _scope.ServiceProvider.GetRequiredService<UserManager<HostUser>>(), roles, _db);
    }

    public async Task DisposeAsync()
    {
        _scope.Dispose();
        await _provider.DisposeAsync();
        await _connection.DisposeAsync();
    }

    private async Task<string[]> AssignedAsync()
    {
        _db.ChangeTracker.Clear();
        return (await _db.RolePermissions.Where(rp => rp.RoleId == _roleId).Select(rp => rp.Permission.Code).ToListAsync())
            .OrderBy(c => c, StringComparer.Ordinal).ToArray();
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldAssignMixedCaseCodes()
    {
        var ok = await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["sales.View", " SALES.edit "]);

        ok.Should().BeTrue();
        (await AssignedAsync()).Should().Equal("SALES.EDIT", "SALES.VIEW");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldAssignOnce_WhenTheSameCodeComesInTwoCases()
    {
        var ok = await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["sales.view", "SALES.VIEW"]);

        ok.Should().BeTrue();
        (await AssignedAsync()).Should().Equal("SALES.VIEW");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldReturnFalseAndKeepTheExistingAssignments_WhenACodeDoesNotExist()
    {
        await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["SALES.VIEW"]);

        var ok = await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["SALES.EDIT", "SALES.DOES-NOT-EXIST"]);

        ok.Should().BeFalse();
        (await AssignedAsync()).Should().Equal("SALES.VIEW");
    }

    [Theory]
    [InlineData("")]
    [InlineData("SALES VIEW")]
    [InlineData("SALES.VI/EW")]
    [InlineData("Saſes.View")]
    [InlineData("SALESVIEW")]
    [InlineData(".VIEW")]
    [InlineData("SALES.")]
    public async Task AssignPermissionsToRoleAsync_ShouldReturnFalseAndKeepTheExistingAssignments_WhenACodeIsInvalid(string bad)
    {
        await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["SALES.VIEW", "SALES.EDIT"]);

        var ok = await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["SALES.DELETE", bad]);

        ok.Should().BeFalse();
        (await AssignedAsync()).Should().Equal("SALES.EDIT", "SALES.VIEW");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldReturnFalseAndKeepTheExistingAssignments_WhenACodeIsTooLong()
    {
        await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["SALES.VIEW"]);

        var ok = await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["SALES.EDIT", new string('x', 101)]);

        ok.Should().BeFalse();
        (await AssignedAsync()).Should().Equal("SALES.VIEW");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldReplaceTheAssignments_AndClearThemForAnEmptyList()
    {
        await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["SALES.VIEW", "SALES.EDIT"]);

        (await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), ["SALES.DELETE"])).Should().BeTrue();
        (await AssignedAsync()).Should().Equal("SALES.DELETE");

        (await _manager.AssignPermissionsToRoleAsync(_roleId.ToString(), [])).Should().BeTrue();
        (await AssignedAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldReturnFalse_WhenTheRoleDoesNotExist()
    {
        (await _manager.AssignPermissionsToRoleAsync(Guid.NewGuid().ToString(), ["SALES.VIEW"])).Should().BeFalse();
    }
}
