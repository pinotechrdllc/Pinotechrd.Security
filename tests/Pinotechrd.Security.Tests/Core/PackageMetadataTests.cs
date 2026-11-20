using System.Reflection;
using FluentAssertions;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class PackageMetadataTests
{
    private const string ExpectedVersion = "1.2.0-preview.5";

    [Theory]
    [InlineData(typeof(PinotechrdAuthManager<>))]
    [InlineData(typeof(IPinotechrdAuthManager<>))]
    public void BuiltAssemblies_ShouldCarryTheReleaseVersion(Type type)
    {
        var informational = type.Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;

        // Source link may append "+<commit>" to the informational version.
        informational.Split('+')[0].Should().Be(ExpectedVersion);
    }

    [Fact]
    public void BothAssemblies_ShouldShareOneVersion()
    {
        var core = typeof(PinotechrdAuthManager<>).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion.Split('+')[0];
        var abstractions = typeof(IPinotechrdAuthManager<>).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion.Split('+')[0];

        core.Should().Be(abstractions);
    }
}
