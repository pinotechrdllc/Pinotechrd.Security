using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>An application entity whose property names collide with the words the session-change matcher looks for.</summary>
public sealed class Widget
{
    public int Id { get; set; }

    public string Role { get; set; } = "";

    public string Schema { get; set; } = "";

    public string SearchPath { get; set; } = "";

    public string Reset { get; set; } = "";

    public string Discard { get; set; } = "";
}

/// <summary>Same properties, mapped to the lower-case snake_case columns an application on PostgreSQL usually has.</summary>
public sealed class SnakeWidget
{
    public int Id { get; set; }

    public string Role { get; set; } = "";

    public string Schema { get; set; } = "";

    public string SearchPath { get; set; } = "";

    public string Reset { get; set; } = "";

    public string Discard { get; set; } = "";
}

public sealed class WidgetDb : PinotechrdSecurityDbContext<HostUser, HostRole>
{
    public WidgetDb(DbContextOptions<WidgetDb> options, ISchemaProvider schemaProvider) : base(options, schemaProvider)
    {
    }

    public DbSet<Widget> Widgets => Set<Widget>();

    public DbSet<SnakeWidget> SnakeWidgets => Set<SnakeWidget>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Widget>(e =>
        {
            e.ToTable("Widgets");
            e.Property(w => w.Role).HasColumnName("Role");
            e.Property(w => w.Schema).HasColumnName("Schema");
            e.Property(w => w.SearchPath).HasColumnName("SearchPath");
            e.Property(w => w.Reset).HasColumnName("Reset");
            e.Property(w => w.Discard).HasColumnName("Discard");
        });

        modelBuilder.Entity<SnakeWidget>(e =>
        {
            e.ToTable("snake_widgets");
            e.Property(w => w.Id).HasColumnName("id");
            e.Property(w => w.Role).HasColumnName("role");
            e.Property(w => w.Schema).HasColumnName("schema");
            e.Property(w => w.SearchPath).HasColumnName("search_path");
            e.Property(w => w.Reset).HasColumnName("reset");
            e.Property(w => w.Discard).HasColumnName("discard");
        });
    }
}

/// <summary>
/// Everything EF Core itself generates for an ordinary model must pass the command interceptor: a false positive of the
/// session-change matcher here would make an application's own queries fail in <c>SearchPath</c> mode. The model has
/// properties named Role, Schema, SearchPath, Reset and Discard, mapped both PascalCase and snake_case.
/// </summary>
public class SessionChangeEfModelTests : IDisposable
{
    private readonly PostgresLikeSession _session = new();

    public SessionChangeEfModelTests()
    {
        _session.Execute(
            "CREATE TABLE \"Widgets\" (\"Id\" INTEGER PRIMARY KEY, \"Role\" TEXT, \"Schema\" TEXT, \"SearchPath\" TEXT, \"Reset\" TEXT, \"Discard\" TEXT);" +
            "CREATE TABLE snake_widgets (id INTEGER PRIMARY KEY, role TEXT, \"schema\" TEXT, search_path TEXT, reset TEXT, discard TEXT);");
    }

    public void Dispose() => _session.Dispose();

    private WidgetDb NewDb()
    {
        var builder = new DbContextOptionsBuilder<WidgetDb>().UseSqlite(_session.Connection);
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);
        return new WidgetDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant("a")));
    }

    /// <summary>
    /// A context whose connection stays open for the whole test (an explicit transaction, as application code often has).
    /// EF Core closes the connection it opened by itself after each command, which would hide a connection marked by an
    /// earlier command; inside a transaction every later command meets that mark.
    /// </summary>
    private WidgetDb NewDb(bool inTransaction)
    {
        var db = NewDb();
        if (inTransaction) db.Database.BeginTransaction();
        return db;
    }

    // ---- PascalCase columns ------------------------------------------------------------------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PascalCaseColumns_ShouldInsertUpdateQueryAndDelete_WithoutAnyRefusal(bool inTransaction)
    {
        using var db = NewDb(inTransaction);

        db.Widgets.AddRange(
            new Widget { Id = 1, Role = "admin", Schema = "s", SearchPath = "p", Reset = "r", Discard = "d" },
            new Widget { Id = 2, Role = "user", Schema = "s2", SearchPath = "p2", Reset = "r2", Discard = "d2" });
        db.SaveChanges();

        var widget = db.Widgets.Single(w => w.Id == 1);
        widget.Role = "root";
        widget.Schema = "s9";
        widget.SearchPath = "p9";
        widget.Reset = "r9";
        widget.Discard = "d9";
        db.SaveChanges();

        db.Widgets.Where(w => w.Role == "root" && w.SearchPath == "p9" && w.Schema == "s9").Select(w => w.Reset).Should().Equal("r9");
        db.Widgets.Where(w => w.Discard == "d2" || w.Reset == "nope").OrderBy(w => w.Role).ThenBy(w => w.SearchPath).Select(w => w.Id).Should().Equal(2);
        db.Widgets.Any(w => w.SearchPath == "p2").Should().BeTrue();

        db.Widgets.Remove(widget);
        db.SaveChanges();
        db.Widgets.Count().Should().Be(1);
        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a", "the connection is still bound after all those commands");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PascalCaseColumns_ShouldRunBulkUpdateAndDelete(bool inTransaction)
    {
        using var db = NewDb(inTransaction);
        db.Widgets.Add(new Widget { Id = 1, Role = "a", SearchPath = "p" });
        db.SaveChanges();

        db.Widgets.Where(w => w.Id == 1).ExecuteUpdate(s => s
            .SetProperty(w => w.Role, "b")
            .SetProperty(w => w.SearchPath, "q")
            .SetProperty(w => w.Reset, "x"));
        db.Widgets.Where(w => w.SearchPath == "q").ExecuteDelete();

        db.Widgets.Count().Should().Be(0);
    }

    // ---- snake_case columns, the usual PostgreSQL spelling -----------------------------------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SnakeCaseColumns_ShouldInsertAndQuery_WithoutAnyRefusal(bool inTransaction)
    {
        using var db = NewDb(inTransaction);

        db.SnakeWidgets.Add(new SnakeWidget { Id = 1, Role = "admin", Schema = "s", SearchPath = "p", Reset = "r", Discard = "d" });
        db.SaveChanges();

        db.SnakeWidgets.Single(w => w.Role == "admin").SearchPath.Should().Be("p");
        db.SnakeWidgets.Where(w => w.Schema == "s" && w.Reset == "r" && w.Discard == "d").Count().Should().Be(1);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SnakeCaseColumns_ShouldUpdateEveryColumn_WithoutAnyRefusal(bool inTransaction)
    {
        using var db = NewDb(inTransaction);
        db.SnakeWidgets.Add(new SnakeWidget { Id = 1 });
        db.SaveChanges();

        var widget = db.SnakeWidgets.Single();
        widget.Role = "root";
        widget.Schema = "s9";
        widget.Reset = "r9";
        widget.Discard = "d9";
        db.SaveChanges();

        db.SnakeWidgets.Single().Role.Should().Be("root");
    }

    // A column named search_path is mapped by many PostgreSQL applications; "UPDATE ... SET search_path = @p" and
    // "WHERE search_path = @p" are what EF Core generates for it, and neither changes the session.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SnakeCaseSearchPathColumn_ShouldBeUpdatable(bool inTransaction)
    {
        using var db = NewDb(inTransaction);
        db.SnakeWidgets.Add(new SnakeWidget { Id = 1, SearchPath = "a" });
        db.SaveChanges();

        var widget = db.SnakeWidgets.Single();
        widget.SearchPath = "b";
        var act = () => db.SaveChanges();

        act.Should().NotThrow("an UPDATE of an ordinary column that happens to be called search_path is not a session change");
        db.SnakeWidgets.Single().SearchPath.Should().Be("b");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SnakeCaseSearchPathColumn_ShouldBeUsableInAWhereClause(bool inTransaction)
    {
        using var db = NewDb(inTransaction);
        db.SnakeWidgets.Add(new SnakeWidget { Id = 1, SearchPath = "a" });
        db.SaveChanges();

        var act = () => db.SnakeWidgets.Where(w => w.SearchPath == "a").ToList();

        act.Should().NotThrow("a comparison with a column called search_path is not a session change");
        db.SnakeWidgets.Count().Should().Be(1, "the next command on the same connection must still be accepted");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SnakeCaseSearchPathColumn_ShouldBeUpdatableOnSeveralRowsInOneSaveChanges(bool inTransaction)
    {
        using var db = NewDb(inTransaction);
        db.SnakeWidgets.AddRange(new SnakeWidget { Id = 1, SearchPath = "a" }, new SnakeWidget { Id = 2, SearchPath = "a" }, new SnakeWidget { Id = 3, SearchPath = "a" });
        db.SaveChanges();

        foreach (var widget in db.SnakeWidgets.ToList()) widget.SearchPath = "b";
        var act = () => db.SaveChanges();

        act.Should().NotThrow("a batch of ordinary UPDATE statements is not a session change");
        db.SnakeWidgets.Count(w => w.SearchPath == "b").Should().Be(3);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SnakeCaseSearchPathColumn_ShouldBeSettableByExecuteUpdate(bool inTransaction)
    {
        using var db = NewDb(inTransaction);
        db.SnakeWidgets.Add(new SnakeWidget { Id = 1, SearchPath = "a" });
        db.SaveChanges();

        var act = () => db.SnakeWidgets.ExecuteUpdate(s => s.SetProperty(w => w.SearchPath, "b"));

        act.Should().NotThrow();
        db.SnakeWidgets.Count().Should().Be(1, "the next command on the same connection must still be accepted");
    }

    // ---- Several operations in one SaveChanges (one batch where the provider batches) --------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SaveChanges_ShouldRunAMixedInsertUpdateDeleteUnitOfWork(bool inTransaction)
    {
        using var db = NewDb(inTransaction);
        db.Widgets.AddRange(new Widget { Id = 1, Role = "a" }, new Widget { Id = 2, Role = "b" }, new Widget { Id = 3, Role = "c" });
        db.SaveChanges();

        db.Widgets.Add(new Widget { Id = 4, Role = "d", Reset = "x" });
        db.Widgets.Single(w => w.Id == 1).Role = "z";
        db.Widgets.Remove(db.Widgets.Single(w => w.Id == 2));
        db.SaveChanges();

        db.Widgets.OrderBy(w => w.Id).Select(w => w.Role).Should().Equal("z", "c", "d");
    }
}
