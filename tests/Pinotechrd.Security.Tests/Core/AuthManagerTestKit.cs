using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>
/// Password hasher that records how it is used. Thread safe, so it can back concurrency tests.
/// </summary>
internal sealed class RecordingPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
{
    private int _hashCalls;
    private int _counter;

    public int HashCalls => Volatile.Read(ref _hashCalls);

    public ConcurrentQueue<(string Hash, string Password)> Verifications { get; } = new();

    public TimeSpan HashDelay { get; set; } = TimeSpan.Zero;

    public string HashPassword(TUser user, string password)
    {
        Interlocked.Increment(ref _hashCalls);
        if (HashDelay > TimeSpan.Zero) Thread.Sleep(HashDelay);
        return "dummy-hash-" + Interlocked.Increment(ref _counter) + "-" + Guid.NewGuid().ToString("N");
    }

    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        Verifications.Enqueue((hashedPassword, providedPassword));
        return PasswordVerificationResult.Failed;
    }
}

/// <summary>
/// Builds a <see cref="PinotechrdAuthManager{TUser}"/> over an NSubstitute <see cref="UserManager{TUser}"/>
/// that behaves like a small stateful Identity backend (security stamp, lockout, two-factor codes bound to the stamp).
/// The user type is a type argument because the dummy password hash cache is static per user type.
/// </summary>
internal sealed class AuthManagerTestKit<TUser> where TUser : BaseSecurityUser, new()
{
    public const string Password = "correct-horse";
    public const string Provider = "Email";
    public const string DefaultTenant = "tenant-a";

    private readonly Dictionary<string, TUser> _usersById = new();
    private readonly Dictionary<string, UserState> _state = new();

    /// <param name="withDataProtection">Whether a data protection provider is given to the manager.</param>
    /// <param name="messageService">Optional message service.</param>
    /// <param name="tenant">Tenant the request context was resolved for; null leaves the context without a tenant.</param>
    /// <param name="withTenantContext">False builds the manager without any <see cref="TenantContext"/>.</param>
    /// <param name="withAttemptStore">False builds the manager without a two-factor attempt store.</param>
    /// <param name="timeProvider">Clock; defaults to a fake clock the test can advance.</param>
    /// <param name="refreshStore">Refresh token store; defaults to a substitute.</param>
    /// <param name="identityValidator">Optional host validator run when tokens are issued.</param>
    /// <param name="dataProvider">Optional provider of the authenticated user; without it the self-service methods find no user.</param>
    public AuthManagerTestKit(
        bool withDataProtection = true,
        IPinotechrdMessageService? messageService = null,
        string? tenant = DefaultTenant,
        bool withTenantContext = true,
        bool withAttemptStore = true,
        FakeTimeProvider? timeProvider = null,
        IRefreshTokenStore? refreshStore = null,
        IIdentityValidator<TUser>? identityValidator = null,
        ISecurityDataProvider? dataProvider = null,
        Microsoft.Extensions.Logging.ILoggerFactory? loggerFactory = null)
    {
        Time = timeProvider ?? new FakeTimeProvider();
        if (withTenantContext)
        {
            TenantContext = new TenantContext();
            if (tenant != null) TenantContext.SetTenant(tenant);
        }
        Attempts = withAttemptStore ? new InMemoryTwoFactorAttemptStore(Time) : null;
        Hasher = new RecordingPasswordHasher<TUser>();
        UserManager = CreateUserManager(Hasher);
        SignInManager = CreateSignInManager(UserManager);
        Engine = Substitute.For<ISecurityEngine>();
        TokenProvider = Substitute.For<ITokenProvider>();
        if (refreshStore == null)
        {
            refreshStore = Substitute.For<IRefreshTokenStore>();
            // A rotation into the consumed token's family is stored, as a real store does while it has the family.
            refreshStore.RotateAsync(default!, default!, default!, default!, default).ReturnsForAnyArgs(Task.FromResult(true));
        }

        RefreshStore = refreshStore;
        DataProtection = withDataProtection ? new EphemeralDataProtectionProvider() : null;

        UserManager.SupportsUserLockout.Returns(true);
        UserManager.SupportsUserTwoFactor.Returns(true);
        UserManager.SupportsUserSecurityStamp.Returns(true);
        UserManager.FindByIdAsync(Arg.Any<string>()).Returns(ci =>
            Task.FromResult(_usersById.GetValueOrDefault(ci.Arg<string>())));
        UserManager.GetUserIdAsync(Arg.Any<TUser>()).Returns(ci => Task.FromResult(ci.Arg<TUser>().Id.ToString()));
        UserManager.GetEmailAsync(Arg.Any<TUser>()).Returns(ci => Task.FromResult<string?>(ci.Arg<TUser>().Email));
        UserManager.GetTwoFactorEnabledAsync(Arg.Any<TUser>()).Returns(ci => Task.FromResult(StateOf(ci.Arg<TUser>()).TwoFactorEnabled));
        UserManager.GetValidTwoFactorProvidersAsync(Arg.Any<TUser>()).Returns(Task.FromResult<IList<string>>([Provider]));
        UserManager.GetSecurityStampAsync(Arg.Any<TUser>()).Returns(ci => Task.FromResult(StateOf(ci.Arg<TUser>()).Stamp));
        UserManager.HasPasswordAsync(Arg.Any<TUser>()).Returns(ci => Task.FromResult(StateOf(ci.Arg<TUser>()).HasPassword));
        UserManager.IsLockedOutAsync(Arg.Any<TUser>()).Returns(ci => Task.FromResult(StateOf(ci.Arg<TUser>()).LockedOut));
        UserManager.UpdateSecurityStampAsync(Arg.Any<TUser>()).Returns(ci =>
        {
            var state = StateOf(ci.Arg<TUser>());
            if (state.StampUpdateFails) return Task.FromResult(IdentityResult.Failed());
            state.Stamp = "stamp-" + Guid.NewGuid().ToString("N");
            return Task.FromResult(IdentityResult.Success);
        });
        UserManager.VerifyTwoFactorTokenAsync(Arg.Any<TUser>(), Arg.Any<string>(), Arg.Any<string>()).Returns(ci =>
            Task.FromResult(ci.ArgAt<string>(2) == CodeFor(ci.Arg<TUser>())));
        UserManager.AccessFailedAsync(Arg.Any<TUser>()).Returns(Task.FromResult(IdentityResult.Success));
        UserManager.GetLockoutEnabledAsync(Arg.Any<TUser>()).Returns(Task.FromResult(true));
        UserManager.ResetAccessFailedCountAsync(Arg.Any<TUser>()).Returns(Task.FromResult(IdentityResult.Success));
        UserManager.GenerateTwoFactorTokenAsync(Arg.Any<TUser>(), Arg.Any<string>()).Returns(ci =>
            Task.FromResult(CodeFor(ci.Arg<TUser>())));

        SignInManager.CheckPasswordSignInAsync(Arg.Any<TUser>(), Arg.Any<string>(), Arg.Any<bool>()).Returns(ci =>
        {
            var state = StateOf(ci.Arg<TUser>());
            if (state.LockedOut) return Task.FromResult(Microsoft.AspNetCore.Identity.SignInResult.LockedOut);
            return Task.FromResult(state.HasPassword && ci.ArgAt<string>(1) == Password
                ? Microsoft.AspNetCore.Identity.SignInResult.Success
                : Microsoft.AspNetCore.Identity.SignInResult.Failed);
        });

        SignInManager.CanSignInAsync(Arg.Any<TUser>()).Returns(Task.FromResult(true));

        UserManager.ChangePasswordAsync(Arg.Any<TUser>(), Arg.Any<string>(), Arg.Any<string>()).Returns(ci =>
        {
            var state = StateOf(ci.Arg<TUser>());
            if (ci.ArgAt<string>(1) != state.CurrentPassword)
                return Task.FromResult(IdentityResult.Failed(new IdentityError { Code = "PasswordMismatch", Description = "Incorrect password." }));
            state.CurrentPassword = ci.ArgAt<string>(2);
            return Task.FromResult(IdentityResult.Success);
        });

        Engine.GetPermissionsAsync(Arg.Any<string>()).Returns(new[] { "permissions.read" });
        TokenProvider.GenerateAccessToken(Arg.Any<IEnumerable<Claim>>()).Returns("access-token");
        TokenProvider.GenerateRefreshToken().Returns("refresh-token");

        Manager = new PinotechrdAuthManager<TUser>(
            UserManager,
            SignInManager,
            Engine,
            TokenProvider,
            RefreshStore,
            Microsoft.Extensions.Options.Options.Create(new PinotechrdSecurityOptions
            {
                Jwt = new JwtSettings
                {
                    Secret = "super-secret-key-with-minimum-length-32",
                    MinimumSecretLength = 32,
                    ExpiryMinutes = 60,
                    RefreshTokenExpiryDays = 7,
                    Issuer = "pinotechrd-tests",
                    Audience = "pinotechrd-tests"
                }
            }),
            customValidator: identityValidator,
            messageService: messageService,
            dataProtectionProvider: DataProtection,
            tenantContext: TenantContext,
            twoFactorAttemptStore: Attempts,
            timeProvider: Time,
            dataProvider: dataProvider,
            loggerFactory: loggerFactory);
    }

    public PinotechrdAuthManager<TUser> Manager { get; }

    public FakeTimeProvider Time { get; }

    public TenantContext? TenantContext { get; }

    public ITwoFactorAttemptStore? Attempts { get; }

    public UserManager<TUser> UserManager { get; }

    public SignInManager<TUser> SignInManager { get; }

    public ISecurityEngine Engine { get; }

    public ITokenProvider TokenProvider { get; }

    public IRefreshTokenStore RefreshStore { get; }

    public RecordingPasswordHasher<TUser> Hasher { get; }

    public IDataProtectionProvider? DataProtection { get; }

    /// <summary>Registers a user that can be found by <paramref name="login"/> (as email) and by id.</summary>
    public TUser AddUser(string login, bool twoFactor = false)
    {
        var user = new TUser { Id = Guid.NewGuid(), UserName = login, Email = login };
        _usersById[user.Id.ToString()] = user;
        _state[user.Id.ToString()] = new UserState
        {
            TwoFactorEnabled = twoFactor,
            Stamp = "stamp-" + Guid.NewGuid().ToString("N")
        };
        UserManager.FindByEmailAsync(login).Returns(Task.FromResult<TUser?>(user));
        return user;
    }

    /// <summary>The password the user currently has, as changed through <c>ChangePasswordAsync</c>.</summary>
    public string PasswordOf(TUser user) => StateOf(user).CurrentPassword;

    public string StampOf(TUser user) => StateOf(user).Stamp;

    public void ChangeStamp(TUser user) => StateOf(user).Stamp = "stamp-changed-" + Guid.NewGuid().ToString("N");

    public void MakeInactive(TUser user) => user.IsActive = false;

    public void RemovePassword(TUser user) => StateOf(user).HasPassword = false;

    public void LockOut(TUser user) => StateOf(user).LockedOut = true;

    public void MakeStampUpdateFail(TUser user) => StateOf(user).StampUpdateFails = true;

    /// <summary>The valid second-factor code of a user. Like real Identity codes, it depends on the security stamp.</summary>
    public string CodeFor(TUser user) => "code-" + StateOf(user).Stamp;

    private UserState StateOf(TUser user) => _state[user.Id.ToString()];

    private sealed class UserState
    {
        public bool TwoFactorEnabled { get; set; }

        public string Stamp { get; set; } = string.Empty;

        public bool LockedOut { get; set; }

        public bool HasPassword { get; set; } = true;

        public string CurrentPassword { get; set; } = Password;

        public bool StampUpdateFails { get; set; }
    }

    private static UserManager<TUser> CreateUserManager(IPasswordHasher<TUser> hasher) =>
        Substitute.For<UserManager<TUser>>(
            Substitute.For<IUserStore<TUser>>(),
            Microsoft.Extensions.Options.Options.Create(new IdentityOptions()),
            hasher,
            new List<IUserValidator<TUser>>(),
            new List<IPasswordValidator<TUser>>(),
            Substitute.For<ILookupNormalizer>(),
            new IdentityErrorDescriber(),
            Substitute.For<IServiceProvider>(),
            Substitute.For<ILogger<UserManager<TUser>>>());

    private static SignInManager<TUser> CreateSignInManager(UserManager<TUser> userManager) =>
        Substitute.For<SignInManager<TUser>>(
            userManager,
            Substitute.For<IHttpContextAccessor>(),
            Substitute.For<IUserClaimsPrincipalFactory<TUser>>(),
            Microsoft.Extensions.Options.Options.Create(new IdentityOptions()),
            Substitute.For<ILogger<SignInManager<TUser>>>(),
            Substitute.For<IAuthenticationSchemeProvider>(),
            Substitute.For<IUserConfirmation<TUser>>());
}
