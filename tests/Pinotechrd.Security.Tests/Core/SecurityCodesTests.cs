using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Tests.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>Module and permission codes are case-insensitive and trimmed; module ids derive from the code.</summary>
public class SecurityCodesTests
{
    // ---- SecurityModuleId --------------------------------------------------------------------

    [Fact]
    public void FromCode_ShouldIgnoreCaseAndSurroundingWhitespace()
    {
        SecurityModuleId.FromCode("sales").Should().Be(SecurityModuleId.FromCode(" SALES "));
        SecurityModuleId.FromCode("Sales").Should().Be(SecurityModuleId.FromCode("SALES"));
    }

    [Fact]
    public void FromCode_ShouldGiveDifferentIdsForDifferentCodes()
    {
        SecurityModuleId.FromCode("SALES").Should().NotBe(SecurityModuleId.FromCode("STOCK"));
    }

    [Fact]
    public void FromCode_ShouldBeAVersion5UuidWithTheRfcVariant()
    {
        var text = SecurityModuleId.FromCode("sales").ToString("D");

        text[14].Should().Be('5', "the version nibble of a UUID is the first digit of the third group");
        "89ab".Should().Contain(text[19].ToString(), "the RFC 9562 variant is 10xx");
    }

    [Fact]
    public void FromCode_ShouldBeStable_ComparedWithAnIndependentUuid5()
    {
        // Computed outside the library: uuid.uuid5(UUID("4f8a2c1e-9d3b-4e7a-8c5f-2b6d1a9e7c30"), "SALES").
        SecurityModuleId.FromCode("sales").Should().Be(Guid.Parse("9ffed6ba-fd0a-5abe-a596-b6d1869a510b"));
        SecurityModuleId.FromCode("GLOBAL").Should().Be(Guid.Parse("6abbf5c0-7905-57af-9e5d-327ad26464c8"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void FromCode_ShouldThrowArgumentException_WhenTheCodeIsEmpty(string code)
    {
        var act = () => SecurityModuleId.FromCode(code);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void FromCode_ShouldThrowArgumentException_WhenTheCodeIsNull()
    {
        var act = () => SecurityModuleId.FromCode(null!);

        act.Should().Throw<ArgumentException>();
    }

    // ---- DbSecurityStore ---------------------------------------------------------------------

    private static SecDb NewDb(SqliteConnection connection)
    {
        var db = SecDbFactory.Create(connection, "a", configure: o =>
        {
            o.TenantSchemaMode = TenantSchemaMode.SearchPath;
            // SQLite has no search_path: the test binds nothing, so it takes responsibility instead of the interceptors.
            o.ApplicationTakesResponsibilityForSearchPath = true;
            o.CatalogSchema = null;
        });
        db.Database.EnsureCreated();
        return db;
    }

    [Theory]
    [InlineData("SALES", true)]
    [InlineData("sales", true)]
    [InlineData(" sales ", true)]
    [InlineData("Sales", true)]
    [InlineData("STOCK", false)]
    [InlineData("SAL", false)]
    public async Task IsModuleActiveAsync_ShouldMatchAModuleStoredInUpperCase_IgnoringCaseAndWhitespace(string code, bool expected)
    {
        using var connection = SecDbFactory.OpenMemory();
        await using var db = NewDb(connection);
        var plan = SubscriptionPlan.Create("Basic", "BASIC", null, null);
        var module = SecurityModule.Create("Sales", "SALES");
        db.SubscriptionPlans.Add(plan);
        db.SecurityModules.Add(module);
        db.SystemSubscriptions.Add(new SystemSubscription
        {
            TenantName = "tenant-a",
            CustomerName = "Acme",
            PlanId = plan.Id,
            IsActive = true,
            StartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1))
        });
        db.SubscriptionPlanModules.Add(new SubscriptionPlanModule { PlanId = plan.Id, ModuleId = module.Id });
        await db.SaveChangesAsync();

        var result = await new DbSecurityStore(db).IsModuleActiveAsync("tenant-a", code);

        result.Should().Be(expected);
    }

    // ---- SecuritySeeder ----------------------------------------------------------------------

    private static readonly (string Name, string Code, string? Description)[] SalesPermissions =
    [
        ("View", "sales.view", null),
        ("Edit", "SALES.EDIT", "edit orders")
    ];

    [Fact]
    public async Task SeedModuleAsync_ShouldCreateTheModuleWithTheDerivedIdAndLinkItsPermissions()
    {
        using var connection = SecDbFactory.OpenMemory();
        await using var db = NewDb(connection);

        await new SecuritySeeder(db).SeedModuleAsync("Sales", "sales", "desc", 1, SalesPermissions);

        var module = await db.SecurityModules.SingleAsync();
        module.Id.Should().Be(SecurityModuleId.FromCode("sales"));
        module.Code.Should().Be("SALES");
        var permissions = await db.SecurityPermissions.OrderBy(p => p.Code).ToListAsync();
        permissions.Select(p => p.Code).Should().Equal("SALES.EDIT", "SALES.VIEW");
        permissions.Should().OnlyContain(p => p.ModuleId == module.Id);
    }

    [Fact]
    public async Task SeedModuleAsync_ShouldNotViolateForeignKeys_OnARelationalProvider()
    {
        using var connection = SecDbFactory.OpenMemory();
        await using var db = NewDb(connection);

        await new SecuritySeeder(db).SeedModuleAsync("Sales", "sales", null, 1, SalesPermissions);

        using var check = connection.CreateCommand();
        check.CommandText = "PRAGMA foreign_key_check";
        using var reader = await check.ExecuteReaderAsync();
        (await reader.ReadAsync()).Should().BeFalse("every permission must point at an existing module");
    }

    [Fact]
    public async Task SeedModuleAsync_ShouldBeIdempotent()
    {
        using var connection = SecDbFactory.OpenMemory();
        await using var db = NewDb(connection);
        var seeder = new SecuritySeeder(db);

        await seeder.SeedModuleAsync("Sales", "sales", null, 1, SalesPermissions);
        await seeder.SeedModuleAsync("Sales", " SALES ", null, 1, SalesPermissions);
        await seeder.SeedModuleAsync("Sales", "Sales", null, 1, SalesPermissions);

        (await db.SecurityModules.CountAsync()).Should().Be(1);
        (await db.SecurityPermissions.CountAsync()).Should().Be(2);
        (await db.SecurityModules.SingleAsync()).Id.Should().Be(SecurityModuleId.FromCode("sales"));
    }

    [Fact]
    public async Task SeedModuleAsync_ShouldFillTheModuleIdOfAnExistingPermissionThatHasNone()
    {
        using var connection = SecDbFactory.OpenMemory();
        await using var db = NewDb(connection);
        // A row written before permissions knew their module: ModuleId is Guid.Empty (foreign keys are off for this setup only).
        await db.Database.ExecuteSqlRawAsync("PRAGMA foreign_keys = OFF");
        db.SecurityPermissions.Add(new SecurityPermission { Name = "View", Code = "SALES.VIEW", ModuleId = Guid.Empty });
        await db.SaveChangesAsync();
        await db.Database.ExecuteSqlRawAsync("PRAGMA foreign_keys = ON");
        db.ChangeTracker.Clear();

        await new SecuritySeeder(db).SeedModuleAsync("Sales", "sales", null, 1, SalesPermissions);

        var view = await db.SecurityPermissions.SingleAsync(p => p.Code == "SALES.VIEW");
        view.ModuleId.Should().Be(SecurityModuleId.FromCode("sales"));
        (await db.SecurityPermissions.CountAsync()).Should().Be(2);
    }

    [Fact]
    public async Task SeedModuleAsync_ShouldKeepTheModuleIdOfAnExistingPermissionThatAlreadyHasOne()
    {
        using var connection = SecDbFactory.OpenMemory();
        await using var db = NewDb(connection);
        var other = SecurityModule.Create("Other", "OTHER");
        db.SecurityModules.Add(other);
        db.SecurityPermissions.Add(new SecurityPermission { Name = "View", Code = "SALES.VIEW", ModuleId = other.Id });
        await db.SaveChangesAsync();

        await new SecuritySeeder(db).SeedModuleAsync("Sales", "sales", null, 1, SalesPermissions);

        (await db.SecurityPermissions.SingleAsync(p => p.Code == "SALES.VIEW")).ModuleId.Should().Be(other.Id);
    }
}
