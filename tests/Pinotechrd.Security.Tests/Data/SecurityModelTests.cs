using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>
/// The model of <c>PinotechrdSecurityDbContext</c>, built on the SQLite relational provider (it accepts schemas in the
/// model and is available without a server). Schemas are only mapped here; isolation between schemas needs PostgreSQL.
/// </summary>
public class SecurityModelTests
{
    private static readonly Type[] CatalogTypes =
    [
        typeof(Tenant), typeof(SubscriptionPlan), typeof(SystemSubscription),
        typeof(SubscriptionPlanModule), typeof(SubscriptionPlanFeature)
    ];

    private static IEntityType Entity(SecDb db, Type type) => db.Model.FindEntityType(type)!;

    // Migration exclusion is stored only in the design-time model.
    private static bool ExcludedFromMigrations(SecDb db, Type type) =>
        db.GetService<IDesignTimeModel>().Model.FindEntityType(type)!.IsTableExcludedFromMigrations();

    // ---- Default mode: the schema is in the model --------------------------------------------

    [Fact]
    public void Model_ShouldFailMentioningUsePinotechrdSecurity_WhenTheOptionIsMissingInDefaultMode()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a", usePinotechrd: false);

        var act = () => db.Model;

        act.Should().Throw<InvalidOperationException>().WithMessage("*UsePinotechrdSecurity*");
    }

    [Fact]
    public void Model_ShouldAlsoFailForTheFirstUse_WhenQueryingWithoutTheOption()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a", usePinotechrd: false);

        var act = () => db.Tenants.ToList();

        act.Should().Throw<InvalidOperationException>().WithMessage("*UsePinotechrdSecurity*");
    }

    [Fact]
    public void Model_ShouldGiveEachTenantItsOwnModelAndMapTheUserTableToThatTenantSchema()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var a = SecDbFactory.Create(connection, "a");
        using var b = SecDbFactory.Create(connection, "b");

        a.Model.Should().NotBeSameAs(b.Model);
        Entity(a, typeof(HostUser)).GetSchema().Should().Be("tenant_a");
        Entity(a, typeof(HostUser)).GetTableName().Should().Be("users");
        Entity(b, typeof(HostUser)).GetSchema().Should().Be("tenant_b");
        a.SchemaName.Should().Be("tenant_a");
        b.SchemaName.Should().Be("tenant_b");
    }

    [Fact]
    public void Model_ShouldBeReusedByASecondScopeOfTheSameTenant()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var first = SecDbFactory.Create(connection, "a");
        using var second = SecDbFactory.Create(connection, "a");

        second.Model.Should().BeSameAs(first.Model);
    }

    [Fact]
    public void Model_ShouldKeepEveryTenantTableInTheTenantSchema_AndTheCatalogInTheCatalogSchema()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a");

        foreach (var type in new[] { typeof(HostUser), typeof(HostRole), typeof(SecurityModule), typeof(SecurityPermission), typeof(RolePermission), typeof(UserModulePermission) })
        {
            Entity(db, type).GetSchema().Should().Be("tenant_a", type.Name);
        }

        foreach (var type in CatalogTypes)
        {
            Entity(db, type).GetSchema().Should().Be("public", type.Name);
        }
    }

    [Fact]
    public void Model_ShouldKeepTheCatalogInTheCatalogSchemaEvenForTwoTenants()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var a = SecDbFactory.Create(connection, "a");
        using var b = SecDbFactory.Create(connection, "b");

        Entity(a, typeof(Tenant)).GetSchema().Should().Be("public");
        Entity(b, typeof(Tenant)).GetSchema().Should().Be("public");
    }

    // ---- SearchPath mode ---------------------------------------------------------------------

    private static SecDb SearchPath(SqliteConnection connection, string? tenant, Action<PinotechrdSecurityModelOptions>? more = null) =>
        SecDbFactory.Create(connection, tenant, configure: o =>
        {
            o.TenantSchemaMode = TenantSchemaMode.SearchPath;
            more?.Invoke(o);
        });

    [Fact]
    public void SearchPath_ShouldShareOneModelAcrossTenants()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var a = SearchPath(connection, "a");
        using var b = SearchPath(connection, "b");

        a.Model.Should().BeSameAs(b.Model);
    }

    [Fact]
    public void SearchPath_ShouldMapUserTablesWithoutASchema_AndReportNoSchemaName()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a");

        db.SchemaName.Should().BeNull();
        foreach (var type in new[] { typeof(HostUser), typeof(HostRole), typeof(SecurityModule), typeof(SecurityPermission), typeof(RolePermission), typeof(UserModulePermission) })
        {
            Entity(db, type).GetSchema().Should().BeNull(type.Name);
        }
    }

    [Fact]
    public void SearchPath_ShouldBuildTheModel_WhenNoTenantIsResolved()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, tenant: null);

        var act = () => db.Model;

        act.Should().NotThrow();
        db.SchemaName.Should().BeNull();
    }

    [Fact]
    public void SearchPath_ShouldPutTheCatalogInTheCatalogSchema_ByDefault()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a");

        CatalogTypes.Should().OnlyContain(type => Entity(db, type).GetSchema() == "public");
    }

    [Fact]
    public void SearchPath_ShouldUseTheConfiguredCatalogSchema()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a", o => o.CatalogSchema = "platform");

        CatalogTypes.Should().OnlyContain(type => Entity(db, type).GetSchema() == "platform");
    }

    [Fact]
    public void SearchPath_ShouldLeaveTheCatalogWithoutASchema_WhenTheCatalogSchemaIsNull()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a", o => o.CatalogSchema = null);

        CatalogTypes.Should().OnlyContain(type => Entity(db, type).GetSchema() == null);
    }

    [Fact]
    public void TwoSearchPathContextsWithDifferentCatalogSchemas_ShouldNotShareAModel()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var one = SearchPath(connection, "a", o => o.CatalogSchema = "one");
        using var two = SearchPath(connection, "a", o => o.CatalogSchema = "two");

        one.Model.Should().NotBeSameAs(two.Model);
        Entity(one, typeof(Tenant)).GetSchema().Should().Be("one");
        Entity(two, typeof(Tenant)).GetSchema().Should().Be("two");
    }

    // ---- Catalog and migrations --------------------------------------------------------------

    [Fact]
    public void ExcludeCatalogFromMigrations_ShouldMarkTheFiveCatalogTables_AndOnlyThose()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a", configure: o => o.ExcludeCatalogFromMigrations = true);

        CatalogTypes.Should().HaveCount(5);
        foreach (var type in CatalogTypes)
        {
            ExcludedFromMigrations(db, type).Should().BeTrue(type.Name);
        }

        foreach (var type in new[] { typeof(HostUser), typeof(HostRole), typeof(SecurityModule), typeof(SecurityPermission), typeof(RolePermission), typeof(UserModulePermission) })
        {
            ExcludedFromMigrations(db, type).Should().BeFalse(type.Name);
        }
    }

    [Fact]
    public void ExcludeCatalogFromMigrations_ShouldBeOffByDefault()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a");

        CatalogTypes.Should().OnlyContain(type => !ExcludedFromMigrations(db, type));
    }

    [Fact]
    public void TheMigrationsSqlOfATenant_ShouldNotCreateCatalogTables_WhenTheyAreExcluded()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a", o => o.ExcludeCatalogFromMigrations = true);

        var script = db.Database.GenerateCreateScript();

        script.Should().Contain("\"users\"");
        script.Should().NotContain("subscription_plans").And.NotContain("system_subscriptions").And.NotContain("\"tenants\"");
    }

    [Fact]
    public void TheGeneratedTenantDdl_ShouldNameNoSchema_InSearchPathMode()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a", o =>
        {
            o.CatalogSchema = null;
            o.ExcludeCatalogFromMigrations = true;
        });

        var script = db.Database.GenerateCreateScript();

        script.Should().Contain("\"users\"");
        script.Should().NotContain("tenant_a").And.NotContain("tenant_b");
    }

    // ---- Catalog has no foreign key into a tenant table -------------------------------------

    [Fact]
    public void SubscriptionPlanModule_ShouldHaveNoForeignKeyToSecurityModule_AndNoModuleNavigation()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a");
        var planModule = Entity(db, typeof(SubscriptionPlanModule));
        var module = Entity(db, typeof(SecurityModule));

        planModule.GetForeignKeys().Should().OnlyContain(fk => fk.PrincipalEntityType.ClrType == typeof(SubscriptionPlan));
        planModule.GetForeignKeys().Should().NotContain(fk => fk.PrincipalEntityType == module);
        planModule.FindNavigation(nameof(SubscriptionPlanModule.Module)).Should().BeNull();
        module.FindNavigation(nameof(SecurityModule.PlanModules)).Should().BeNull();
        module.GetReferencingForeignKeys().Should().NotContain(fk => fk.DeclaringEntityType == planModule);
    }

    [Fact]
    public void SubscriptionPlanModule_ShouldKeepAnIndexOnTheModuleId()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a");

        Entity(db, typeof(SubscriptionPlanModule)).GetIndexes()
            .Should().Contain(index => index.Properties.Select(p => p.Name).SequenceEqual(new[] { nameof(SubscriptionPlanModule.ModuleId) }));
    }

    [Fact]
    public void TheCatalog_ShouldCreateWithoutAForeignKeyToTheTenantModuleTable()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a");

        var script = db.Database.GenerateCreateScript();

        var start = script.IndexOf("CREATE TABLE \"subscription_plan_modules\"", StringComparison.Ordinal);
        start.Should().BeGreaterThanOrEqualTo(0);
        var statement = script[start..script.IndexOf(");", start, StringComparison.Ordinal)];
        statement.Should().Contain("REFERENCES \"subscription_plans\"");
        statement.Should().NotContain("security_modules");
    }

    // ---- Refresh token tables (opt-in) -------------------------------------------------------

    private static IEnumerable<IEntityType> RefreshTokenTables(SecDb db) =>
        db.Model.GetEntityTypes().Where(t => t.GetTableName() is "refresh_tokens" or "refresh_token_families");

    [Fact]
    public void Model_ShouldNotMapRefreshTokenTables_ByDefault()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a");

        RefreshTokenTables(db).Should().BeEmpty();
    }

    [Fact]
    public void Model_ShouldNotMapRefreshTokenTables_WhenTheFlagIsOffInSearchPathMode()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a");

        RefreshTokenTables(db).Should().BeEmpty();
    }

    [Fact]
    public void Model_ShouldMapBothRefreshTokenTablesInTheTenantSchema_WhenMapRefreshTokensIsOn()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var a = SecDbFactory.Create(connection, "a", configure: o => o.MapRefreshTokens = true);
        using var b = SecDbFactory.Create(connection, "b", configure: o => o.MapRefreshTokens = true);

        RefreshTokenTables(a).Select(t => t.GetTableName()).Should().BeEquivalentTo("refresh_tokens", "refresh_token_families");
        RefreshTokenTables(a).Should().OnlyContain(t => t.GetSchema() == a.SchemaName);
        RefreshTokenTables(b).Should().OnlyContain(t => t.GetSchema() == b.SchemaName);
        a.SchemaName.Should().NotBe(b.SchemaName);
    }

    [Fact]
    public void Model_ShouldKeepRefreshTokenTablesOutOfTheCatalogSchema_EvenWithACustomCatalogSchema()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a", configure: o =>
        {
            o.MapRefreshTokens = true;
            o.CatalogSchema = "platform";
        });

        RefreshTokenTables(db).Should().HaveCount(2).And.OnlyContain(t => t.GetSchema() == db.SchemaName && t.GetSchema() != "platform");
    }

    [Fact]
    public void Model_ShouldMapRefreshTokenTablesWithoutASchema_InSearchPathModeWhenTheFlagIsOn()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a", o => o.MapRefreshTokens = true);

        RefreshTokenTables(db).Should().HaveCount(2).And.OnlyContain(t => t.GetSchema() == null);
    }

    [Fact]
    public void Model_ShouldKeyRefreshTokensByAColumnNamedTokenHashAndStoreNoTokenColumn()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a", configure: o => o.MapRefreshTokens = true);

        var tokens = RefreshTokenTables(db).Single(t => t.GetTableName() == "refresh_tokens");
        var table = Microsoft.EntityFrameworkCore.Metadata.StoreObjectIdentifier.Table("refresh_tokens", tokens.GetSchema());
        var columns = tokens.GetProperties().Select(p => p.GetColumnName(table)).ToList();

        tokens.FindPrimaryKey()!.Properties.Single().GetColumnName(table).Should().Be("token_hash");
        columns.Should().BeEquivalentTo("token_hash", "tenant_id", "user_id", "family_id", "security_stamp", "expires_at", "consumed_at", "revoked_at");
    }

    [Fact]
    public void TheCreateScript_ShouldContainRefreshTokenTables_OnlyWhenTheFlagIsOn()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var off = SearchPath(connection, "a");
        using var on = SearchPath(connection, "a", o => o.MapRefreshTokens = true);

        off.Database.GenerateCreateScript().Should().NotContain("refresh_token");
        on.Database.GenerateCreateScript().Should().Contain("refresh_tokens").And.Contain("refresh_token_families");
    }

    // ---- Two-factor attempt table (opt-in) ---------------------------------------------------

    private static IEnumerable<IEntityType> TwoFactorAttemptTables(SecDb db) =>
        db.Model.GetEntityTypes().Where(t => t.GetTableName() == "two_factor_attempts");

    [Fact]
    public void Model_ShouldNotMapTheTwoFactorAttemptTable_ByDefault()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a");

        TwoFactorAttemptTables(db).Should().BeEmpty();
    }

    [Fact]
    public void Model_ShouldNotMapTheTwoFactorAttemptTable_WhenTheFlagIsOffInSearchPathMode()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a");

        TwoFactorAttemptTables(db).Should().BeEmpty();
    }

    [Fact]
    public void Model_ShouldMapTheTwoFactorAttemptTableInTheTenantSchema_WhenMapTwoFactorAttemptsIsOn()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var a = SecDbFactory.Create(connection, "a", configure: o => o.MapTwoFactorAttempts = true);
        using var b = SecDbFactory.Create(connection, "b", configure: o => o.MapTwoFactorAttempts = true);

        TwoFactorAttemptTables(a).Should().ContainSingle().Which.GetSchema().Should().Be(a.SchemaName);
        TwoFactorAttemptTables(b).Should().ContainSingle().Which.GetSchema().Should().Be(b.SchemaName);
        a.SchemaName.Should().NotBe(b.SchemaName);
    }

    [Fact]
    public void Model_ShouldKeepTheTwoFactorAttemptTableOutOfTheCatalogSchema_EvenWithACustomCatalogSchema()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a", configure: o =>
        {
            o.MapTwoFactorAttempts = true;
            o.CatalogSchema = "platform";
        });

        TwoFactorAttemptTables(db).Should().ContainSingle().Which.GetSchema().Should().Be(db.SchemaName).And.NotBe("platform");
    }

    [Fact]
    public void Model_ShouldMapTheTwoFactorAttemptTableWithoutASchema_InSearchPathModeWhenTheFlagIsOn()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SearchPath(connection, "a", o => o.MapTwoFactorAttempts = true);

        TwoFactorAttemptTables(db).Should().ContainSingle().Which.GetSchema().Should().BeNull();
    }

    [Fact]
    public void Model_ShouldKeyTheTwoFactorAttemptsByAHashColumnAndStoreNoChallengeColumn()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var db = SecDbFactory.Create(connection, "a", configure: o => o.MapTwoFactorAttempts = true);

        var attempts = TwoFactorAttemptTables(db).Single();
        var table = StoreObjectIdentifier.Table("two_factor_attempts", attempts.GetSchema());
        var columns = attempts.GetProperties().Select(p => p.GetColumnName(table)).ToList();

        attempts.FindPrimaryKey()!.Properties.Single().GetColumnName(table).Should().Be("challenge_hash");
        columns.Should().BeEquivalentTo("challenge_hash", "count", "exhausted", "expires_at");
    }

    [Fact]
    public void Model_ShouldNotMapRefreshTokenTables_WhenOnlyTheTwoFactorFlagIsOn_AndTheOtherWayRound()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var attemptsOnly = SecDbFactory.Create(connection, "a", configure: o => o.MapTwoFactorAttempts = true);
        using var tokensOnly = SecDbFactory.Create(connection, "a", configure: o => o.MapRefreshTokens = true);

        RefreshTokenTables(attemptsOnly).Should().BeEmpty();
        TwoFactorAttemptTables(tokensOnly).Should().BeEmpty();
    }

    [Fact]
    public void TheCreateScript_ShouldContainTheTwoFactorAttemptTable_OnlyWhenTheFlagIsOn()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var off = SearchPath(connection, "a");
        using var on = SearchPath(connection, "a", o => o.MapTwoFactorAttempts = true);

        off.Database.GenerateCreateScript().Should().NotContain("two_factor_attempts");
        on.Database.GenerateCreateScript().Should().Contain("two_factor_attempts").And.Contain("challenge_hash");
    }
}
