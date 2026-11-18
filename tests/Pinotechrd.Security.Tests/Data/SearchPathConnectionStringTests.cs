using System.Data;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>
/// <c>TenantSchemaMode.SearchPath</c> refuses connection strings under which a bound session path cannot be trusted
/// (README, "SearchPath mode in detail"). The rule is checked as a pure function over the string, and through the real
/// interceptors on a connection that reports the string under test.
/// </summary>
public class SearchPathConnectionStringTests
{
    // ---- The pure rule -----------------------------------------------------------------------

    [Theory]
    [InlineData("Host=h;Database=d;Multiplexing=true")]
    [InlineData("Host=h;Database=d;Multiplexing=True")]
    [InlineData("Host=h;Database=d;MULTIPLEXING=TRUE")]
    [InlineData("Host=h;Database=d;Multiplexing=yes")]
    [InlineData("Host=h;Database=d;Multiplexing=1")]
    [InlineData("Host=h;Database=d;Multiplexing = true")]
    [InlineData("Host=h;Database=d;Multiplexing=  true  ")]
    [InlineData("Host=h;Database=d;No Reset On Close=true")]
    [InlineData("Host=h;Database=d;NoResetOnClose=yes")]
    [InlineData("Host=h;Database=d;noresetonclose=True")]
    [InlineData("Host=h;Database=d;No Reset On Close=1")]
    [InlineData("Host=h;Database=d;Search Path=tenant_b")]
    [InlineData("Host=h;Database=d;SearchPath=tenant_b")]
    [InlineData("Host=h;Database=d;search path=public")]
    [InlineData("Host=h;Database=d;Search Path=\"$user\", public")]
    [InlineData("Host=h;Database=d;Options=-c search_path=tenant_b")]
    [InlineData("Host=h;Database=d;Options=-csearch_path=tenant_b")]
    [InlineData("Host=h;Database=d;Options=-c SEARCH_PATH=tenant_b")]
    [InlineData("Host=h;Database=d;Options=-c search\\_path=tenant_b")]
    [InlineData("Host=h;Database=d;Options=-c search-path=tenant_b")]
    [InlineData("Host=h;Database=d;Options=-c statement_timeout=5 -c search_path=tenant_b")]
    [InlineData("Host=h;Database=d;Options=--search_path=tenant_b")]
    [InlineData("Host=h;Database=d;Options=--search-path=tenant_b")]
    public void AnalyzeConnectionString_ShouldRefuse_WhenTheStringBreaksTheOnePhysicalConnectionRule(string connectionString)
    {
        InternalApi.AnalyzeConnectionString(connectionString).Should().NotBeNullOrWhiteSpace();
    }

    [Theory]
    [InlineData("Host=h;Database=d;Multiplexing=true", "Multiplexing")]
    [InlineData("Host=h;Database=d;No Reset On Close=true", "No Reset On Close")]
    [InlineData("Host=h;Database=d;Search Path=x", "Search Path")]
    [InlineData("Host=h;Database=d;Options=-c search_path=x", "search_path")]
    public void AnalyzeConnectionString_ShouldNameTheOffendingSetting(string connectionString, string expected)
    {
        InternalApi.AnalyzeConnectionString(connectionString).Should().Contain(expected);
    }

    [Theory]
    [InlineData("Host=h;Database=d")]
    [InlineData("Host=h;Database=d;Username=u;Password=p;Pooling=true;Maximum Pool Size=20")]
    [InlineData("Host=h;Database=d;Multiplexing=false")]
    [InlineData("Host=h;Database=d;Multiplexing=False")]
    [InlineData("Host=h;Database=d;Multiplexing=no")]
    [InlineData("Host=h;Database=d;Multiplexing=0")]
    [InlineData("Host=h;Database=d;No Reset On Close=false")]
    [InlineData("Host=h;Database=d;Search Path=")]
    [InlineData("Host=h;Database=d;Search Path=   ")]
    [InlineData("Host=h;Database=d;Options=-c statement_timeout=5000")]
    [InlineData("Host=h;Database=d;Options=-c lock_timeout=100 -c application_name=svc")]
    [InlineData("Host=h;Database=d;Application Name=search")]
    [InlineData("")]
    public void AnalyzeConnectionString_ShouldAccept_APlainString_AndExplicitlyDisabledOptions(string connectionString)
    {
        InternalApi.AnalyzeConnectionString(connectionString).Should().BeNull();
    }

    [Fact]
    public void AnalyzeConnectionString_ShouldRefuse_AStringItCannotParse()
    {
        InternalApi.AnalyzeConnectionString("Host=h;Multiplexing").Should().NotBeNullOrWhiteSpace("an unreadable string cannot be shown to be safe");
    }

    // ---- Through the real interceptors -------------------------------------------------------

    [Theory]
    [InlineData("Data Source=db;Multiplexing=true")]
    [InlineData("Data Source=db;No Reset On Close=true")]
    [InlineData("Data Source=db;NoResetOnClose=yes")]
    [InlineData("Data Source=db;Search Path=tenant_b")]
    [InlineData("Data Source=db;Options=-c search_path=tenant_b")]
    [InlineData("Data Source=db;Options=-c search\\_path=tenant_b")]
    [InlineData("Data Source=db;Options=-c search-path=tenant_b")]
    public void Open_ShouldThrowAndLeaveTheConnectionClosed_WhenTheConnectionStringIsUnsafe(string connectionString)
    {
        using var session = new PostgresLikeSession(connectionString);
        using var db = SearchPathContexts.Create(session, "a");

        var act = () => db.Database.OpenConnection();

        act.Should().Throw<InvalidOperationException>().WithMessage("*TenantSchemaMode.SearchPath*");
        session.Connection.State.Should().Be(ConnectionState.Closed);
        session.SetConfigCalls.Should().Be(0, "nothing is bound on a refused connection");
        session.Path.Should().Be(PostgresLikeSession.DefaultPath);
    }

    [Fact]
    public async Task OpenAsync_ShouldThrowAndLeaveTheConnectionClosed_WhenTheConnectionStringIsUnsafe()
    {
        using var session = new PostgresLikeSession("Data Source=db;Multiplexing=true");
        using var db = SearchPathContexts.Create(session, "a");

        var act = () => db.Database.OpenConnectionAsync();

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*Multiplexing*");
        session.Connection.State.Should().Be(ConnectionState.Closed);
        session.SetConfigCalls.Should().Be(0);
    }

    [Fact]
    public void Query_ShouldNeverReachTheDatabase_WhenTheConnectionStringIsUnsafe()
    {
        using var session = new PostgresLikeSession("Data Source=db;Multiplexing=true");
        using var db = SearchPathContexts.Create(session, "a");

        var act = () => db.Tenants.ToList();

        act.Should().Throw<InvalidOperationException>().WithMessage("*Multiplexing*");
        session.Connection.State.Should().Be(ConnectionState.Closed);
        session.SetConfigCalls.Should().Be(0);
    }

    [Fact]
    public void Open_ShouldKeepRefusing_OnEveryAttemptWithTheSameUnsafeString()
    {
        using var session = new PostgresLikeSession("Data Source=db;No Reset On Close=true");
        using var db = SearchPathContexts.Create(session, "a");

        for (var i = 0; i < 3; i++)
        {
            var act = () => db.Database.OpenConnection();
            act.Should().Throw<InvalidOperationException>().WithMessage("*No Reset On Close*", $"attempt {i}");
            session.Connection.State.Should().Be(ConnectionState.Closed);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Data Source=db;Multiplexing=false")]
    [InlineData("Data Source=db;No Reset On Close=false;Search Path=")]
    public void Open_ShouldBindTheTenantSchema_WhenTheConnectionStringIsSafe(string? connectionString)
    {
        using var session = new PostgresLikeSession(connectionString);
        using var db = SearchPathContexts.Create(session, "a");

        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a");
    }
}
