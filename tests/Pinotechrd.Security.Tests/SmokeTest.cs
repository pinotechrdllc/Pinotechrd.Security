using FluentAssertions;
using Xunit;

namespace Pinotechrd.Security.Tests;

public class SmokeTest
{
    [Fact]
    public void TestSetup_ShouldBeCorrect()
    {
        true.Should().BeTrue();
    }
}
