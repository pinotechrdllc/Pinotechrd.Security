using System.Collections.Concurrent;
using System.Globalization;
using System.Text;

namespace Pinotechrd.Security.Data;

/// <summary>
/// Recognises SQL that changes the session state the <c>search_path</c> binding depends on. A guard against mistakes in
/// application SQL sent through EF Core, not a security boundary.
/// </summary>
/// <remarks>
/// <para>
/// The text is tokenised the way PostgreSQL does (with <c>standard_conforming_strings</c> on, its default): standard
/// strings with doubled quotes, <c>E'..'</c> with backslash escapes, <c>U&amp;'..'</c>, bit and national strings, quoted
/// identifiers (unquoted to their name), <c>U&amp;".."</c> identifiers (always counted as a change: escapes can spell any
/// setting name, and EF Core never generates them), dollar quotes where one can start, nested block comments, and line
/// comments ended by <c>\n</c> or <c>\r</c>.
/// The tokens are split into statements at <c>;</c> and each statement is judged on its own.
/// </para>
/// <para>A statement changes the session when it is one of:</para>
/// <list type="bullet">
/// <item><description><c>SET [SESSION|LOCAL]</c> of <c>search_path</c>, <c>schema</c>, <c>role</c>, <c>session authorization</c> /
/// <c>session_authorization</c> or <c>standard_conforming_strings</c>, in any form (<c>TO</c>, <c>=</c>, <c>FROM CURRENT</c>);</description></item>
/// <item><description><c>RESET</c> of those settings, or <c>RESET ALL</c>; <c>DISCARD ALL</c>;</description></item>
/// <item><description><c>ALTER ROLE|USER|DATABASE|SYSTEM ... SET|RESET</c> of those settings (or <c>RESET ALL</c>);</description></item>
/// <item><description>any statement that calls <c>set_config</c> (schema-qualified or quoted too), unless its first argument is
/// exactly one plain string literal, immediately followed by a comma, naming another setting;</description></item>
/// <item><description>any statement that writes to <c>pg_settings</c> (<c>UPDATE</c>, <c>INSERT INTO</c>, <c>DELETE FROM</c>,
/// <c>MERGE INTO</c>, plain, <c>pg_catalog.</c>-qualified or quoted), which is equivalent to <c>SET</c>.</description></item>
/// </list>
/// <para>
/// The bodies of <c>DO</c> blocks and of <c>CREATE [OR REPLACE] FUNCTION|PROCEDURE</c> are scanned with the same rules (a
/// statement inside them may also start after <c>BEGIN</c>, <c>THEN</c>, <c>ELSE</c> or <c>LOOP</c>). Inside them, <c>EXECUTE</c>
/// of exactly one string literal, optionally in parentheses, is scanned; any other <c>EXECUTE</c> (a concatenation,
/// <c>format(...)</c>, a variable) cannot be checked and is refused. <c>PREPARE ... AS</c> is scanned; <c>EXECUTE</c> of a
/// prepared name is allowed.
/// Setting and keyword names are compared case-insensitively after unquoting.
/// </para>
/// <para>
/// It cannot see what server-side functions and procedures already in the database do when they are called (including
/// dynamic SQL they assemble at run time), nor raw ADO.NET commands. A change it misses persists for every later command
/// on that connection until the connection closes, because the binder does not re-read the path per command. The boundary
/// against hostile SQL is not having SQL injection, and not having such functions in the database; stronger isolation
/// needs a database role or login per tenant.
/// </para>
/// </remarks>
internal static class SessionChangeDetector
{
    private const int MaxCachedLength = 8_192;
    private const int MaxCachedEntries = 10_000;
    private static readonly ConcurrentDictionary<string, Verdict> Cache = new(StringComparer.Ordinal);

    private readonly record struct Verdict(string? Change, int Statements);

    /// <summary>Returns a short description of the session change found, or <see langword="null"/>.</summary>
    public static string? Find(string? sql) => Analyze(sql).Change;

    /// <summary>Whether the text holds more than one statement.</summary>
    public static bool HasSeveralStatements(string? sql) => Analyze(sql).Statements > 1;

    private static Verdict Analyze(string? sql)
    {
        if (string.IsNullOrEmpty(sql)) return default;
        if (Cache.TryGetValue(sql, out var cached)) return cached;

        var statements = Lexer.Statements(sql);
        string? change = null;
        foreach (var statement in statements)
        {
            change = Statement(statement, body: false, depth: 0);
            if (change != null) break;
        }

        var verdict = new Verdict(change, statements.Count);
        if (sql.Length <= MaxCachedLength && Cache.Count < MaxCachedEntries)
        {
            Cache.TryAdd(sql, verdict);
        }

        return verdict;
    }

    private static readonly HashSet<string> GuardedSettings = new(StringComparer.OrdinalIgnoreCase)
    {
        "search_path", "role", "session_authorization", "standard_conforming_strings"
    };

    private static readonly HashSet<string> BodyStatementStarts = new(StringComparer.OrdinalIgnoreCase)
    {
        "begin", "then", "else", "loop"
    };

    private static string? Statement(IReadOnlyList<Token> tokens, bool body, int depth)
    {
        if (tokens.Count == 0) return null;
        if (depth > 8) return "nesting too deep to check";

        foreach (var token in tokens)
        {
            if (token.Kind == TokenKind.Undecodable) return "U&-quoted identifier, refused because it can spell any setting name";
        }

        var change = Leading(tokens, 0, depth);
        if (change != null) return change;

        if (body)
        {
            // In a PL/pgSQL or SQL body a statement may also start right after a block keyword.
            for (var i = 0; i + 1 < tokens.Count; i++)
            {
                if (tokens[i].IsKeyword && BodyStatementStarts.Contains(tokens[i].Text))
                {
                    change = Leading(tokens, i + 1, depth);
                    if (change != null) return change;
                }
            }

            // EXECUTE of exactly one string literal, optionally in parentheses: scan the literal as SQL.
            // Anything else (a concatenation, format(...), a variable) cannot be checked, so it is refused.
            for (var i = 0; i < tokens.Count; i++)
            {
                if (!tokens[i].IsWord("execute")) continue;
                var literal = SingleLiteralAt(tokens, i + 1, out var next);
                if (literal == null || next < tokens.Count && !(tokens[next].IsWord("into") || tokens[next].IsWord("using") || tokens[next].IsWord("strict")))
                {
                    return "EXECUTE of a string built at run time";
                }

                change = Text(literal, body: false, depth + 1);
                if (change != null) return change;
            }
        }

        return SetConfigCall(tokens) ?? PgSettingsWrite(tokens);
    }

    /// <summary>Returns the text of one string literal at <paramref name="at"/>, optionally parenthesised.</summary>
    private static string? SingleLiteralAt(IReadOnlyList<Token> t, int at, out int next)
    {
        next = at;
        if (at < t.Count && t[at].IsString)
        {
            next = at + 1;
            return t[at].Text;
        }

        if (at + 2 < t.Count && t[at].IsOperator("(") && t[at + 1].IsString && t[at + 2].IsOperator(")"))
        {
            next = at + 3;
            return t[at + 1].Text;
        }

        return null;
    }

    /// <summary>
    /// A write to the <c>pg_settings</c> view (<c>UPDATE</c>, <c>INSERT INTO</c>, <c>DELETE FROM</c>, <c>MERGE INTO</c>,
    /// plain, <c>pg_catalog.</c>-qualified or quoted) anywhere in the statement, including a data-modifying CTE.
    /// Updating <c>pg_settings</c> is equivalent to <c>SET</c>.
    /// </summary>
    private static string? PgSettingsWrite(IReadOnlyList<Token> t)
    {
        for (var i = 0; i < t.Count; i++)
        {
            int target;
            if (t[i].IsWord("update")) target = i + 1;
            else if ((t[i].IsWord("insert") || t[i].IsWord("merge")) && i + 1 < t.Count && t[i + 1].IsWord("into")) target = i + 2;
            else if (t[i].IsWord("delete") && i + 1 < t.Count && t[i + 1].IsWord("from")) target = i + 2;
            else continue;

            if (target < t.Count && t[target].IsWord("only")) target++;
            if (target + 2 < t.Count && IsName(t[target], "pg_catalog") && t[target + 1].IsOperator(".")) target += 2;
            if (target < t.Count && IsName(t[target], "pg_settings")) return "write to pg_settings";
        }

        return null;
    }

    private static bool IsName(Token token, string name) =>
        token.Kind is TokenKind.Word or TokenKind.QuotedIdentifier && token.Text.Equals(name, StringComparison.OrdinalIgnoreCase);

    private static string? Text(string sql, bool body, int depth)
    {
        foreach (var statement in Lexer.Statements(sql))
        {
            var change = Statement(statement, body, depth);
            if (change != null) return change;
        }

        return null;
    }

    /// <summary>Judges the statement that starts at <paramref name="start"/> by its leading keywords.</summary>
    private static string? Leading(IReadOnlyList<Token> t, int start, int depth)
    {
        if (start >= t.Count || !t[start].IsKeyword) return null;
        var i = start;

        switch (t[i].Text.ToLowerInvariant())
        {
            case "set":
                return SetOrReset(t, i + 1, isSet: true);
            case "reset":
                return SetOrReset(t, i + 1, isSet: false);
            case "discard":
                return i + 1 < t.Count && t[i + 1].IsWord("all") ? "DISCARD ALL" : null;
            case "alter":
                if (i + 1 < t.Count && (t[i + 1].IsWord("role") || t[i + 1].IsWord("user") || t[i + 1].IsWord("database") || t[i + 1].IsWord("system")))
                {
                    for (var j = i + 2; j < t.Count; j++)
                    {
                        if (t[j].IsWord("set") || t[j].IsWord("reset"))
                        {
                            var change = SetOrReset(t, j + 1, t[j].IsWord("set"), allowSessionKeywords: false);
                            if (change != null) return "ALTER " + t[i + 1].Text.ToUpperInvariant() + " ... " + change;
                        }
                    }
                }

                return null;
            case "do":
                return Bodies(t, i + 1, depth);
            case "create":
                for (var j = i + 1; j < t.Count && j <= i + 4; j++)
                {
                    if (t[j].IsWord("function") || t[j].IsWord("procedure")) return Bodies(t, j + 1, depth);
                }

                return null;
            case "prepare":
                for (var j = i + 1; j < t.Count; j++)
                {
                    if (t[j].IsWord("as")) return Statement(Slice(t, j + 1), body: false, depth + 1);
                }

                return null;
            default:
                return null;
        }
    }

    private static string? SetOrReset(IReadOnlyList<Token> t, int i, bool isSet, bool allowSessionKeywords = true)
    {
        var verb = isSet ? "SET" : "RESET";
        if (i >= t.Count) return null;

        if (allowSessionKeywords && isSet && (t[i].IsWord("session") || t[i].IsWord("local")))
        {
            if (t[i].IsWord("session") && i + 1 < t.Count && t[i + 1].IsWord("authorization")) return "SET SESSION AUTHORIZATION";
            i++;
            if (i >= t.Count) return null;
        }

        if (t[i].IsWord("session") && i + 1 < t.Count && t[i + 1].IsWord("authorization")) return verb + " SESSION AUTHORIZATION";
        if (!isSet && t[i].IsWord("all")) return "RESET ALL";
        if (isSet && t[i].IsWord("schema")) return "SET SCHEMA (search_path)";

        if (t[i].Kind is TokenKind.Word or TokenKind.QuotedIdentifier)
        {
            // A setting name, possibly dotted (app.user_id); only the guarded single names matter.
            var dotted = i + 1 < t.Count && t[i + 1].IsOperator(".");
            if (!dotted && GuardedSettings.Contains(t[i].Text))
            {
                var name = t[i].Text.ToLowerInvariant();
                return name == "role" ? verb + " ROLE" : verb + " " + name;
            }
        }

        return null;
    }

    /// <summary>Scans every string or dollar-quoted token after <paramref name="from"/> as a body.</summary>
    private static string? Bodies(IReadOnlyList<Token> t, int from, int depth)
    {
        for (var j = from; j < t.Count; j++)
        {
            if (!t[j].IsString) continue;
            var change = Text(t[j].Text, body: true, depth + 1);
            if (change != null) return change;
        }

        return null;
    }

    /// <summary>
    /// <c>set_config(...)</c> anywhere in the statement, unless the first argument is one plain literal followed by a comma
    /// that names an unguarded setting.
    /// </summary>
    private static string? SetConfigCall(IReadOnlyList<Token> t)
    {
        for (var i = 0; i + 1 < t.Count; i++)
        {
            if (!(t[i].Kind is TokenKind.Word or TokenKind.QuotedIdentifier)
                || !t[i].Text.Equals("set_config", StringComparison.OrdinalIgnoreCase)
                || !t[i + 1].IsOperator("("))
            {
                continue;
            }

            var plain = i + 3 < t.Count
                && t[i + 2].Kind == TokenKind.PlainString
                && t[i + 3].IsOperator(",");
            if (!plain) return "set_config with a computed setting name";
            if (GuardedSettings.Contains(t[i + 2].Text)) return "set_config(" + t[i + 2].Text.ToLowerInvariant() + ")";
        }

        return null;
    }

    private static List<Token> Slice(IReadOnlyList<Token> t, int from)
    {
        var list = new List<Token>(Math.Max(0, t.Count - from));
        for (var i = from; i < t.Count; i++) list.Add(t[i]);
        return list;
    }

    internal enum TokenKind
    {
        Word,
        QuotedIdentifier,
        PlainString,
        OtherString,
        Operator,
        Other,
        Undecodable
    }

    internal readonly record struct Token(TokenKind Kind, string Text)
    {
        public bool IsKeyword => Kind == TokenKind.Word;

        public bool IsString => Kind is TokenKind.PlainString or TokenKind.OtherString;

        public bool IsWord(string word) => Kind == TokenKind.Word && Text.Equals(word, StringComparison.OrdinalIgnoreCase);

        public bool IsOperator(string op) => Kind == TokenKind.Operator && Text == op;
    }

    /// <summary>PostgreSQL-like tokeniser. Whitespace includes Unicode spaces, so they cannot glue keywords together.</summary>
    internal static class Lexer
    {
        public static List<List<Token>> Statements(string sql)
        {
            var result = new List<List<Token>>();
            var current = new List<Token>();
            foreach (var token in Tokens(sql))
            {
                if (token.IsOperator(";"))
                {
                    if (current.Count > 0) result.Add(current);
                    current = new List<Token>();
                    continue;
                }

                current.Add(token);
            }

            if (current.Count > 0) result.Add(current);
            return result;
        }

        private static bool IsIdentStart(char c) => char.IsLetter(c) || c == '_' || c >= '\u0080' && !char.IsWhiteSpace(c);

        private static bool IsIdentPart(char c) => IsIdentStart(c) || char.IsDigit(c) || c == '$';

        public static IEnumerable<Token> Tokens(string s)
        {
            var i = 0;
            while (i < s.Length)
            {
                var c = s[i];
                if (char.IsWhiteSpace(c)) { i++; continue; }

                // Comments
                if (c == '-' && i + 1 < s.Length && s[i + 1] == '-')
                {
                    while (i < s.Length && s[i] != '\n' && s[i] != '\r') i++;
                    continue;
                }

                if (c == '/' && i + 1 < s.Length && s[i + 1] == '*')
                {
                    var level = 0;
                    while (i < s.Length)
                    {
                        if (s[i] == '/' && i + 1 < s.Length && s[i + 1] == '*') { level++; i += 2; }
                        else if (s[i] == '*' && i + 1 < s.Length && s[i + 1] == '/') { level--; i += 2; if (level == 0) break; }
                        else i++;
                    }

                    continue;
                }

                // Prefixed strings and identifiers: E'..', B'..', X'..', N'..', U&'..', U&".."
                if ((c is 'u' or 'U') && i + 2 < s.Length && s[i + 1] == '&' && (s[i + 2] == '\'' || s[i + 2] == '"'))
                {
                    var quote = s[i + 2];
                    var raw = Quoted(s, ref i, i + 2, quote, backslashEscapes: false);
                    var escape = Uescape(s, ref i);
                    if (quote == '"')
                    {
                        // Fail closed: an escaped identifier can spell any setting name, and EF Core never generates one.
                        yield return new Token(TokenKind.Undecodable, raw);
                    }
                    else
                    {
                        yield return new Token(TokenKind.OtherString, DecodeUnicode(raw, escape) ?? raw);
                    }

                    continue;
                }

                if ((c is 'e' or 'E' or 'b' or 'B' or 'x' or 'X' or 'n' or 'N') && i + 1 < s.Length && s[i + 1] == '\''
                    && (i == 0 || !IsIdentPart(s[i - 1])))
                {
                    var backslash = c is 'e' or 'E';
                    yield return new Token(TokenKind.OtherString, Quoted(s, ref i, i + 1, '\'', backslash));
                    continue;
                }

                if (c == '\'')
                {
                    yield return new Token(TokenKind.PlainString, Quoted(s, ref i, i, '\'', backslashEscapes: false));
                    continue;
                }

                if (c == '"')
                {
                    yield return new Token(TokenKind.QuotedIdentifier, Quoted(s, ref i, i, '"', backslashEscapes: false));
                    continue;
                }

                // Dollar quote: $tag$ ... $tag$, only where a token starts (never inside an identifier such as a$q$).
                if (c == '$')
                {
                    // Tag: empty, or an identifier start followed by identifier characters other than '$'.
                    var end = i + 1;
                    if (end < s.Length && IsIdentStart(s[end]))
                    {
                        end++;
                        while (end < s.Length && IsIdentPart(s[end]) && s[end] != '$') end++;
                    }

                    if (end < s.Length && s[end] == '$')
                    {
                        var tag = s.Substring(i, end - i + 1);
                        var bodyStart = end + 1;
                        var close = s.IndexOf(tag, bodyStart, StringComparison.Ordinal);
                        var body = close < 0 ? s[bodyStart..] : s[bodyStart..close];
                        i = close < 0 ? s.Length : close + tag.Length;
                        yield return new Token(TokenKind.OtherString, body);
                        continue;
                    }

                    // $1 parameter or a stray $
                    i++;
                    while (i < s.Length && char.IsDigit(s[i])) i++;
                    yield return new Token(TokenKind.Other, "$");
                    continue;
                }

                if (IsIdentStart(c))
                {
                    var start = i;
                    while (i < s.Length && IsIdentPart(s[i])) i++;
                    yield return new Token(TokenKind.Word, s[start..i]);
                    continue;
                }

                if (char.IsDigit(c))
                {
                    while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] == '.' || s[i] == '_')) i++;
                    yield return new Token(TokenKind.Other, "0");
                    continue;
                }

                if (c == '@' && i + 1 < s.Length && IsIdentStart(s[i + 1]))
                {
                    i++;
                    while (i < s.Length && IsIdentPart(s[i])) i++;
                    yield return new Token(TokenKind.Other, "@param");
                    continue;
                }

                if (c is '(' or ')' or ',' or ';' or '.' or '[' or ']')
                {
                    i++;
                    yield return new Token(TokenKind.Operator, c.ToString());
                    continue;
                }

                // Operator characters run together (|| , = , <> ...); a comment start ends them.
                var opStart = i;
                while (i < s.Length && "+-*/<>=~!@#%^&|`?:".Contains(s[i])
                       && !(s[i] == '-' && i + 1 < s.Length && s[i + 1] == '-')
                       && !(s[i] == '/' && i + 1 < s.Length && s[i + 1] == '*'))
                {
                    i++;
                }

                if (i == opStart) i++;
                yield return new Token(TokenKind.Operator, s[opStart..i]);
            }
        }

        /// <summary>Reads a quoted run starting at <paramref name="quoteAt"/>; doubled quotes stand for one.</summary>
        private static string Quoted(string s, ref int i, int quoteAt, char quote, bool backslashEscapes)
        {
            var sb = new StringBuilder();
            var j = quoteAt + 1;
            while (j < s.Length)
            {
                var ch = s[j];
                if (backslashEscapes && ch == '\\' && j + 1 < s.Length)
                {
                    sb.Append(s[j + 1] switch { 'n' => '\n', 'r' => '\r', 't' => '\t', 'b' => '\b', 'f' => '\f', var other => other });
                    j += 2;
                    continue;
                }

                if (ch == quote)
                {
                    if (j + 1 < s.Length && s[j + 1] == quote) { sb.Append(quote); j += 2; continue; }
                    j++;
                    break;
                }

                sb.Append(ch);
                j++;
            }

            i = j;
            return sb.ToString();
        }

        /// <summary>Consumes an optional <c>UESCAPE 'c'</c> clause and returns the escape character.</summary>
        private static char Uescape(string s, ref int i)
        {
            var j = i;
            while (j < s.Length && char.IsWhiteSpace(s[j])) j++;
            if (j + 7 <= s.Length && s.AsSpan(j, 7).Equals("UESCAPE", StringComparison.OrdinalIgnoreCase))
            {
                var k = j + 7;
                while (k < s.Length && char.IsWhiteSpace(s[k])) k++;
                if (k + 2 < s.Length && s[k] == '\'' && s[k + 2] == '\'')
                {
                    i = k + 3;
                    return s[k + 1];
                }
            }

            return '\\';
        }

        /// <summary>Decodes <c>\XXXX</c>, <c>\+XXXXXX</c> and a doubled escape; <see langword="null"/> when malformed.</summary>
        private static string? DecodeUnicode(string raw, char escape)
        {
            var sb = new StringBuilder();
            for (var j = 0; j < raw.Length; j++)
            {
                if (raw[j] != escape) { sb.Append(raw[j]); continue; }
                if (j + 1 < raw.Length && raw[j + 1] == escape) { sb.Append(escape); j++; continue; }

                var six = j + 1 < raw.Length && raw[j + 1] == '+';
                var digits = six ? 6 : 4;
                var from = six ? j + 2 : j + 1;
                if (from + digits > raw.Length
                    || !int.TryParse(raw.AsSpan(from, digits), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code)
                    || code > 0x10FFFF || code is >= 0xD800 and <= 0xDFFF)
                {
                    return null;
                }

                sb.Append(char.ConvertFromUtf32(code));
                j = from + digits - 1;
            }

            return sb.ToString();
        }
    }
}
