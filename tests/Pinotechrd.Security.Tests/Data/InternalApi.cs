using System.Reflection;
using Pinotechrd.Security.Data;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>
/// Reaches the library's internal pure functions by reflection: the library declares no InternalsVisibleTo and the test
/// project may not edit it. Every call is a thin pass-through, so the tests below assert only on the returned values.
/// </summary>
internal static class InternalApi
{
    private static readonly Assembly Library = typeof(PinotechrdSecurityModelOptions).Assembly;

    private const BindingFlags Any = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;

    private static readonly MethodInfo FindMethod = Library
        .GetType("Pinotechrd.Security.Data.SessionChangeDetector", throwOnError: true)!
        .GetMethod("Find", Any)!;

    private static readonly MethodInfo SeveralMethod = Library
        .GetType("Pinotechrd.Security.Data.SessionChangeDetector", throwOnError: true)!
        .GetMethod("HasSeveralStatements", Any)!;

    private static readonly MethodInfo AnalyzeMethod = Library
        .GetType("Pinotechrd.Security.Data.SearchPathBinder", throwOnError: true)!
        .GetMethod("AnalyzeConnectionString", Any)!;

    /// <summary>SessionChangeDetector.Find: a description of the session change, or null.</summary>
    public static string? Find(string? sql) => (string?)FindMethod.Invoke(null, [sql]);

    /// <summary>SessionChangeDetector.HasSeveralStatements.</summary>
    public static bool HasSeveralStatements(string? sql) => (bool)SeveralMethod.Invoke(null, [sql])!;

    /// <summary>SearchPathBinder.AnalyzeConnectionString: the refusal reason, or null when the string is acceptable.</summary>
    public static string? AnalyzeConnectionString(string connectionString) => (string?)AnalyzeMethod.Invoke(null, [connectionString]);
}
