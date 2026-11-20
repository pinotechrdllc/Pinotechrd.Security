using FluentAssertions;
using Xunit;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>
/// The text matcher that recognises SQL which changes the session state the search_path binding depends on. The cases are
/// derived from the documented behaviour (README, "SearchPath mode in detail") and from PostgreSQL's own grammar, not from the
/// matcher's patterns. The theories whose name starts with "Bypass" hold inputs that really change the session on PostgreSQL
/// and that the matcher does not recognise: each failing row is a finding.
/// </summary>
public class SessionChangeDetectorTests
{
    // ---- Documented positives ----------------------------------------------------------------

    [Theory]
    [InlineData("SET search_path TO x")]
    [InlineData("set search_path = x")]
    [InlineData("set \"search_path\" = x")]
    [InlineData("SET SESSION search_path TO x")]
    [InlineData("SET LOCAL search_path TO x")]
    [InlineData("SET search_path TO DEFAULT")]
    [InlineData("ALTER ROLE r SET search_path TO x")]
    [InlineData("ALTER DATABASE d SET search_path TO x")]
    [InlineData("select set_config('search_path','x',false)")]
    [InlineData("SELECT set_config('search_path', 'x', true)")]
    [InlineData("SELECT SET_CONFIG ( 'SEARCH_PATH' , 'x' , false )")]
    [InlineData("select set_config(name, 'x', false) from names")]
    [InlineData("select set_config(@p0, 'x', false)")]
    [InlineData("RESET ALL")]
    [InlineData("reset all")]
    [InlineData("RESET search_path")]
    [InlineData("RESET \"search_path\"")]
    [InlineData("DISCARD ALL")]
    [InlineData("SET ROLE r")]
    [InlineData("SET LOCAL ROLE r")]
    [InlineData("SET SESSION ROLE r")]
    [InlineData("SET SESSION AUTHORIZATION u")]
    [InlineData("SET LOCAL SESSION AUTHORIZATION u")]
    [InlineData("RESET ROLE")]
    [InlineData("RESET SESSION AUTHORIZATION")]
    [InlineData("SET/**/search_path TO x")]
    [InlineData("SET /* a */ search_path /* b */ TO x")]
    [InlineData("SET -- c\n search_path TO x")]
    [InlineData("-- leading comment\nSET ROLE r")]
    public void Find_ShouldRecogniseTheDocumentedSessionChanges(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Find_ShouldNameTheKindOfChange_SoTheErrorMessageIsUseful()
    {
        InternalApi.Find("SET search_path TO x").Should().Contain("search_path");
        InternalApi.Find("SET ROLE r").Should().Contain("ROLE");
        InternalApi.Find("DISCARD ALL").Should().Contain("DISCARD");
    }

    // ---- Documented negatives ----------------------------------------------------------------

    [Theory]
    [InlineData("SELECT current_setting('search_path')")]
    [InlineData("SHOW search_path")]
    [InlineData("UPDATE t SET role = 'x'")]
    [InlineData("UPDATE t SET role = 'x', schema = 'y' WHERE id = 1")]
    [InlineData("SELECT reset_token FROM users")]
    [InlineData("UPDATE users SET reset_token = NULL WHERE id = 1")]
    [InlineData("SELECT discard_reason, role FROM t WHERE role = 'admin'")]
    [InlineData("SELECT set_config('app.user_id', 'u1', false)")]
    [InlineData("INSERT INTO t (id, role, schema) VALUES (1, 'a', 'b')")]
    [InlineData("SELECT 1")]
    [InlineData("SELECT 'reset all'")]
    [InlineData("/* SET search_path TO x */ SELECT 1")]
    [InlineData("-- SET ROLE r\nSELECT 1")]
    [InlineData("")]
    public void Find_ShouldNotFlagReadsOrOrdinaryNames(string sql)
    {
        InternalApi.Find(sql).Should().BeNull();
    }

    [Fact]
    public void Find_ShouldReturnNull_ForNullText()
    {
        InternalApi.Find(null).Should().BeNull();
    }

    [Theory]
    [InlineData("SELECT 'search_path = x'")]
    [InlineData("UPDATE settings SET note = 'search_path = public'")]
    public void Find_ShouldNotFlagALiteralContainingAnAssignment_BecauseLiteralsAreLexed(string sql)
    {
        InternalApi.Find(sql).Should().BeNull("string literals are lexed, so text inside one is data");
    }

    // ---- Several statements ------------------------------------------------------------------

    [Theory]
    [InlineData("SET search_path TO x; SELECT 1")]
    [InlineData("SET search_path TO x;SELECT 1")]
    [InlineData("SET ROLE r;\nSELECT * FROM t")]
    [InlineData("SELECT 1; SET ROLE r")]
    [InlineData("SELECT 1;\r\n  SELECT 2")]
    [InlineData("SET search_path TO x; -- c\nSELECT 1")]
    public void HasSeveralStatements_ShouldBeTrue_WhenAStatementFollowsASemicolon(string sql)
    {
        InternalApi.HasSeveralStatements(sql).Should().BeTrue();
    }

    [Theory]
    [InlineData("SET search_path TO x")]
    [InlineData("SET search_path TO x;")]
    [InlineData("SET search_path TO x;   ")]
    [InlineData("SET search_path TO x; -- the end")]
    [InlineData("SET search_path TO x; /* the end */")]
    [InlineData("SELECT 1 /* ; SELECT 2 */")]
    [InlineData("")]
    [InlineData(null)]
    public void HasSeveralStatements_ShouldBeFalse_ForOneStatement(string? sql)
    {
        InternalApi.HasSeveralStatements(sql).Should().BeFalse();
    }

    // ---- Documented limit: server-side code --------------------------------------------------

    [Fact]
    public void Readme_ShouldStateThatServerSideCodeAndPieceByPieceNamesAreNotChecked()
    {
        var readme = File.ReadAllText(RepoFile("README.md"));
        var section = readme[readme.IndexOf("**`SearchPath` mode in detail.**", StringComparison.Ordinal)..];
        section = section[..section.IndexOf("**The catalog.**", StringComparison.Ordinal)];

        var notChecked = section[section.IndexOf("Not checked:", StringComparison.Ordinal)..];
        notChecked.Should().Contain("server-side functions or procedures");
        notChecked.Should().Contain("dynamic SQL");
        notChecked.Should().Contain("raw ADO.NET");
    }

    // ---- Dynamic EXECUTE inside server-side code ---------------------------------------------

    [Theory]
    [InlineData("DO $$ BEGIN EXECUTE format('SET %I TO %L', 'search' || '_path', 'x'); END $$")]
    [InlineData("CREATE FUNCTION f() RETURNS void AS $$ BEGIN EXECUTE 'SE' || 'T search_' || 'path TO x'; END $$ LANGUAGE plpgsql; SELECT f()")]
    [InlineData("DO $$ BEGIN EXECUTE 'SE' || 'T ROLE r'; END $$")]
    [InlineData("DO $$ DECLARE q text := 'SELECT 1'; BEGIN EXECUTE q; END $$")]
    [InlineData("CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ BEGIN EXECUTE format('SELECT %L', 1); END $$")]
    public void Find_ShouldRefuseAnExecuteBuiltAtRunTime_BecauseItCannotBeChecked(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull("failing closed: a concatenation, format(...) or a variable cannot be read");
    }

    [Theory]
    [InlineData("DO $$ BEGIN EXECUTE ('SET search_path TO x'); END $$")]
    [InlineData("DO $$ BEGIN EXECUTE 'SET search_path TO x'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE ( 'SET ROLE r' ); END $$")]
    [InlineData("CREATE FUNCTION f() RETURNS void AS $$ BEGIN EXECUTE ('SELECT set_config(''search_path'', ''x'', false)'); END $$ LANGUAGE plpgsql")]
    public void Find_ShouldScanTheLiteralOfAnExecute_AndRefuseAChange(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    [InlineData("DO $$ BEGIN EXECUTE 'SELECT 1'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE ('SELECT 1'); END $$")]
    [InlineData("CREATE FUNCTION f() RETURNS int AS $$ BEGIN EXECUTE 'UPDATE t SET role = ''x'''; RETURN 1; END $$ LANGUAGE plpgsql")]
    public void Find_ShouldAllowAnExecuteOfOnePlainLiteralThatChangesNothing(string sql)
    {
        InternalApi.Find(sql).Should().BeNull();
    }

    [Fact]
    public void Readme_ShouldStateThatDynamicExecuteInServerSideCodeIsRefused_AndWhatItCostsMigrations()
    {
        var readme = File.ReadAllText(RepoFile("README.md"));

        readme.Should().Contain("`EXECUTE` of exactly one string literal");
        readme.Should().Contain("cannot be checked and is refused");
        readme.Should().Contain("a migration that creates such a function must run outside `SearchPath` mode");
    }

    // ---- Writes to pg_settings ---------------------------------------------------------------

    [Theory]
    [InlineData("UPDATE pg_settings SET setting = 'x' WHERE name = 'search_path'")]
    [InlineData("update pg_settings set setting = 'x' where name = 'role'")]
    [InlineData("UPDATE pg_catalog.pg_settings SET setting = 'x' WHERE name = 'search_path'")]
    [InlineData("UPDATE \"pg_settings\" SET setting = 'x' WHERE name = 'search_path'")]
    [InlineData("UPDATE pg_catalog.\"pg_settings\" SET setting = 'x'")]
    [InlineData("UPDATE \"pg_catalog\".\"pg_settings\" AS s SET setting = 'x'")]
    [InlineData("INSERT INTO pg_settings (name, setting) VALUES ('search_path', 'x')")]
    [InlineData("INSERT INTO pg_catalog.pg_settings (name, setting) VALUES ('search_path', 'x')")]
    [InlineData("DELETE FROM pg_settings WHERE name = 'search_path'")]
    [InlineData("DELETE FROM ONLY pg_catalog.pg_settings")]
    [InlineData("MERGE INTO pg_settings s USING (SELECT 1) t ON true WHEN MATCHED THEN UPDATE SET setting = 'x'")]
    [InlineData("MERGE INTO pg_catalog.pg_settings s USING (SELECT 1) t ON true WHEN MATCHED THEN DELETE")]
    [InlineData("WITH u AS (UPDATE pg_settings SET setting = 'x' WHERE name = 'search_path' RETURNING 1) SELECT * FROM u")]
    [InlineData("WITH u AS (UPDATE pg_catalog.pg_settings SET setting = 'x' RETURNING 1) SELECT 1")]
    [InlineData("WITH d AS (DELETE FROM pg_settings RETURNING 1) SELECT 1")]
    [InlineData("SELECT 1; UPDATE pg_settings SET setting = 'x'")]
    [InlineData("DO $$ BEGIN UPDATE pg_settings SET setting = 'x' WHERE name = 'search_path'; END $$")]
    public void Find_ShouldRefuseAWriteToPgSettings(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull("a write to pg_settings is a SET");
    }

    [Theory]
    [InlineData("SELECT name, setting FROM pg_settings WHERE name = 'search_path'")]
    [InlineData("SELECT * FROM pg_catalog.pg_settings")]
    [InlineData("SELECT * FROM \"pg_settings\"")]
    [InlineData("WITH s AS (SELECT * FROM pg_settings) SELECT count(*) FROM s")]
    [InlineData("UPDATE settings SET note = 'pg_settings'")]
    [InlineData("UPDATE t SET pg_settings = 1")]
    [InlineData("INSERT INTO pg_settings_log (id) VALUES (1)")]
    [InlineData("SELECT 'UPDATE pg_settings SET setting = 1'")]
    [InlineData("/* UPDATE pg_settings SET setting = 1 */ SELECT 1")]
    public void Find_ShouldAllowReadingPgSettingsAndNamesThatOnlyLookSimilar(string sql)
    {
        InternalApi.Find(sql).Should().BeNull();
    }

    [Theory]
    [InlineData("DO $$ BEGIN SET search_path TO x; END $$")]
    [InlineData("DO $$ BEGIN PERFORM set_config('search_path', 'x', false); END $$")]
    [InlineData("DO $$ BEGIN EXECUTE 'SET search_path TO x'; END $$")]
    [InlineData("DO $body$ BEGIN PERFORM set_config('search_path', 'x', false); END $body$")]
    public void Find_ShouldStillSeeALiteralPathChangeInsideADoBlock(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    // ---- Attempts to defeat the matcher ------------------------------------------------------
    // Every row below is valid PostgreSQL that changes the session (or leaves it indistinguishable from a changed one).
    // A failing row is an input the matcher does not recognise: report it, do not weaken the row.

    [Theory]
    // Spellings the task asked to try that the matcher does handle: they pass and guard against regressions.
    [InlineData("SeLeCt SeT_cOnFiG('SeArCh_PaTh','x',fAlSe)")]
    [InlineData("   \t\r\n  SET ROLE r")]
    [InlineData("SELECT 1;SET ROLE r")]
    [InlineData("SELECT 1\n;\n  SET search_path TO x")]
    [InlineData("BEGIN; SET LOCAL search_path TO x; COMMIT")]
    [InlineData("SELECT pg_catalog.set_config('search_path','x',false)")]
    [InlineData("SELECT set_config(E'search_path','x',false)")]
    [InlineData("SELECT set_config(U&'search\\005fpath','x',false)")]
    [InlineData("SELECT set_config(('search_path'),'x',false)")]
    [InlineData("SELECT set_config(lower('SEARCH_PATH'),'x',false)")]
    [InlineData("WITH s AS (SELECT set_config('search_path','x',false)) SELECT * FROM s")]
    [InlineData("SELECT 1 WHERE (SELECT set_config('search_path','x',false)) IS NOT NULL")]
    [InlineData("-- hide\nSET search_path TO x")]
    [InlineData("SET\u00A0search_path\u2003TO x")]
    [InlineData("SET\u2003ROLE\u00A0r")]
    public void Find_ShouldRecogniseTheSpellingsItHandles(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // E'' constants decode octal, hexadecimal and Unicode escapes before the server runs the text (PostgreSQL docs,
    // "String Constants with C-Style Escapes"). Each row changes the session, or defines code that does when it runs.
    [InlineData("DO $$ BEGIN EXECUTE E'\\x53ET search_path TO x'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE E'\\123ET search_path TO x'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE E'\\163\\145\\164 search_path TO x'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE E'\\u0053ET search_path TO x'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE E'\\U00000053ET search_path TO x'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE E'SET search\\x5fpath TO x'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE E'SET search\\137path TO x'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE E'SET\\x20ROLE r'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE (E'\\x52ESET ALL'); END $$")]
    [InlineData("CREATE FUNCTION f() RETURNS void AS $$ BEGIN EXECUTE E'\\x53ET search_path TO x'; END $$ LANGUAGE plpgsql")]
    [InlineData("DO $$ BEGIN EXECUTE E'\\x53ELECT set_config(''search_path'', ''x'', false)'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE E'SELECT \\x73et_config(''search_path'', ''x'', false)'; END $$")]
    public void BypassEscapeStringEscapes_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // PostgreSQL joins string constants separated by whitespace holding a line break, and reads the later parts with the
    // first part's rules, so the parts cannot be scanned one by one.
    [InlineData("SELECT E'x'\n'\\'', set_config('search_path','x',false) --'")]
    [InlineData("SELECT E'x' -- c\n'\\'', set_config('search_path','x',false) --'")]
    [InlineData("DO 'BEGIN SE'\n'T search_path TO x; END'")]
    // PostgreSQL 14 and older read 1E'..' as a number followed by an escape string constant.
    [InlineData("SELECT 1E'a\\'', set_config('search_path','x',false) --'")]
    public void BypassStringContinuationAndNumberPrefix_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // Escapes PostgreSQL rejects: the text cannot be decoded, so the statement is refused (fail closed).
    [InlineData("SELECT E'\\u12'")]
    [InlineData("SELECT E'\\U0011FFFF'")]
    [InlineData("SELECT E'\\uD83D'")]
    [InlineData("SELECT E'\\uDE00'")]
    [InlineData("SELECT E'\\x00'")]
    [InlineData("SELECT E'\\000'")]
    [InlineData("DO $$ BEGIN EXECUTE E'\\u005'; END $$")]
    [InlineData("SELECT E'\\uZZZZ SET search_path TO x'")]
    [InlineData("SELECT E'\\u' || 'tail'")]
    [InlineData("SELECT E'\\UFFFFFFFF'")]
    [InlineData("SELECT E'\\uD83D\\x41'")]
    [InlineData("SELECT E'\\uD83D plain'")]
    public void Find_ShouldRefuseAnEscapeStringItCannotDecode(string sql)
    {
        InternalApi.Find(sql).Should().Contain("escape string constant");
    }

    [Theory]
    // Valid escapes that change nothing stay allowed.
    [InlineData("SELECT E'caf\\xC3\\xA9 \\303\\251 \\u00e9 \\U0001F600 \\uD83D\\uDE00'")]
    [InlineData("SELECT E'tab\\there\\nnew line \\\\ backslash \\' quote \\x no hex digit'")]
    [InlineData("SELECT E'\\101 \\8 \\1234 \\x414'")]
    [InlineData("SELECT E'\\uD83D\\U0000DE00 \\U0000D83D\\uDE00'")]
    [InlineData("SELECT 'a' 'b'")]
    [InlineData("SELECT 1e5, 1E+5, 'x'")]
    [InlineData("SELECT E'\\")]
    [InlineData("DO $$ BEGIN EXECUTE E'SELECT \\x31'; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE E'UPDATE t SET name = \\'x\\''; END $$")]
    public void Find_ShouldAllowEscapeStringsThatChangeNothing(string sql)
    {
        InternalApi.Find(sql).Should().BeNull();
    }

    [Fact]
    public void Find_ShouldRefuseAHarmlessStringContinuationToo_BecauseItsPartsCannotBeScannedApart()
    {
        InternalApi.Find("SELECT 'a'\r\n  'b'").Should().Contain("continued after a line break");
    }

    [Theory]
    // Nested block comments: PostgreSQL nests them, so the whole /* /* */ */ is one comment; the matcher ends it at the first */.
    [InlineData("SELECT set_config/* /* */ */('search_path','x',false)")]
    [InlineData("SET /* /* */ */ ROLE r")]
    [InlineData("SET /* /* */ */ SESSION AUTHORIZATION u")]
    [InlineData("RESET /* /* */ */ ALL")]
    [InlineData("DISCARD /* /* */ */ ALL")]
    public void BypassNestedBlockComments_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // A comment marker inside a string literal or a quoted identifier is not a comment, but the matcher strips from it.
    [InlineData("SELECT '--'; SET search_path TO x")]
    [InlineData("SELECT 1 AS \"--\"; SET ROLE r")]
    [InlineData("SELECT '/*'; SET search_path TO x; SELECT '*/'")]
    [InlineData("SELECT '--', set_config('search_path','x',false)")]
    [InlineData("SELECT '/*' AS a, set_config('search_path','x',false), '*/' AS b")]
    public void BypassCommentMarkersInsideLiterals_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // PostgreSQL ends a -- comment at a lone carriage return too; the matcher only at \n.
    [InlineData("-- c\rSET search_path TO x")]
    [InlineData("SELECT 1 -- c\r; SET ROLE r")]
    public void BypassLineCommentEndedByCarriageReturn_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    [InlineData("SET search_path TO x -- c\r; SELECT * FROM t")]
    [InlineData("SET search_path TO x; SELECT '--'")]
    [InlineData("SET search_path TO x /* ; */; SELECT 1")]
    public void HasSeveralStatements_ShouldBeTrue_WhenCommentSyntaxTriesToHideTheSecondStatement(string sql)
    {
        InternalApi.HasSeveralStatements(sql).Should().BeTrue();
    }

    [Theory]
    // Quoted identifier with a Unicode escape spells search_path without the letters s-e-a-r-c-h-_-p-a-t-h in a row.
    [InlineData("SET U&\"search\\005fpath\" TO x")]
    [InlineData("SET U&\"\\0073earch_path\" = x")]
    [InlineData("SET U&\"search!005fpath\" TO x UESCAPE '!'")]
    [InlineData("RESET U&\"search\\005fpath\"")]
    public void BypassUnicodeEscapedIdentifier_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // set_config documents "anything other than a plain literal" but a concatenation that STARTS with a literal slips through.
    [InlineData("SELECT set_config('search_' || 'path', 'x', false)")]
    [InlineData("SELECT set_config('search_'||'path','x',false)")]
    [InlineData("SELECT set_config('search' 'path', 'x', false)")]
    [InlineData("DO $$ BEGIN PERFORM set_config('search_' || 'path', 'x', false); END $$")]
    // A quoted function name is the same function.
    [InlineData("SELECT pg_catalog.\"set_config\"('search_path','x',false)")]
    [InlineData("SELECT \"set_config\"('search_path','x',false)")]
    public void BypassSetConfigSpellings_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // SET SCHEMA 'x' is PostgreSQL's alias for SET search_path TO 'x'.
    [InlineData("SET SCHEMA 'tenant_b'")]
    [InlineData("SET SESSION SCHEMA 'tenant_b'")]
    [InlineData("SET LOCAL SCHEMA 'tenant_b'")]
    public void BypassSetSchemaAlias_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // The role and the session authorization are also plain settings: they can be set without the special syntax.
    [InlineData("SET \"role\" TO r")]
    [InlineData("SET role TO r")]
    [InlineData("SET \"session_authorization\" TO u")]
    [InlineData("SET session_authorization TO u")]
    [InlineData("SET session_authorization = 'u'")]
    [InlineData("RESET \"role\"")]
    [InlineData("RESET session_authorization")]
    [InlineData("SELECT set_config('role', 'r', false)")]
    [InlineData("SELECT set_config('session_authorization', 'u', false)")]
    public void BypassRoleAndAuthorizationAsPlainSettings_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // The role forms are only matched at the start of a statement, so inside a DO block they pass, while
    // "SET search_path" inside the same block is matched: the README lists only "server-side functions" as unchecked.
    [InlineData("DO $$ BEGIN SET ROLE r; END $$")]
    [InlineData("DO $$ BEGIN RESET ALL; END $$")]
    [InlineData("DO $$ BEGIN RESET ROLE; END $$")]
    [InlineData("DO $$ BEGIN EXECUTE 'SET ROLE r'; END $$")]
    [InlineData("DO $$ BEGIN SET SESSION AUTHORIZATION u; END $$")]
    public void BypassRoleChangesInsideADoBlock_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    [Theory]
    // FROM CURRENT re-sets the path to its present value: a SET statement the matcher does not know, harmless in effect
    // for a bound connection but a change of session state by the documented definition ("an assignment to search_path in any form").
    [InlineData("SET search_path FROM CURRENT")]
    [InlineData("SET SESSION search_path FROM CURRENT")]
    public void BypassSetFromCurrent_ShouldBeRecognised(string sql)
    {
        InternalApi.Find(sql).Should().NotBeNull();
    }

    // ---- Helpers -----------------------------------------------------------------------------

    internal static string RepoFile(string relative)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Pinotechrd.Security.slnx")))
        {
            directory = directory.Parent;
        }

        directory.Should().NotBeNull("the test runs from a build folder inside the repository");
        return Path.Combine(directory!.FullName, relative);
    }
}
