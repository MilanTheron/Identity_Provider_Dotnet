using idp.Models;
using idp.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using idp.Data;
using System.Security.Cryptography;

namespace idp.Tests.Services;

public class AuthServiceTests
{
    private readonly TokenService _tokenService;
    private readonly BackupCodeService _backupCodeService;
    private readonly LoginDelayService _delayService;
    private readonly AuthService _authService;

    public AuthServiceTests()
    {
        SecurityService.UseRsaForTesting(RSA.Create(2048));
        
        var db = new AppDbContext(
            new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options);
        
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Hmac:Key", Convert.ToBase64String(new byte[32]) },
                { "Jwt:Issuer", "test" },
                { "Jwt:KeyId", "test-key" }
            })
            .Build();
        
        _tokenService = new TokenService(db, config, NullLogger<TokenService>.Instance);
        _backupCodeService = new BackupCodeService(NullLogger<BackupCodeService>.Instance);
        _delayService = new LoginDelayService(NullLogger<LoginDelayService>.Instance);
        _authService = new AuthService(_tokenService, _backupCodeService, _delayService);
    }

    [Fact]
    public void SetEmailVerification_SetsHashAndExpiry()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "" };
        var rawToken= TokenService.GenerateSecureToken();
        
        _authService.SetEmailVerification(user, rawToken);
        
        Assert.False(string.IsNullOrWhiteSpace(user.EmailVerificationTokenHash));
        Assert.NotNull(user.EmailVerificationTokenExpiry);
        Assert.True(user.EmailVerificationTokenExpiry > DateTime.UtcNow.AddHours(23));
        Assert.True(user.EmailVerificationTokenExpiry <= DateTime.UtcNow.AddHours(25));
    }

    [Fact]
    public void SetEmailVerification_HashDiffersFromRawToken()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "" };
        var rawToken = "plaintoken";
        
        _authService.SetEmailVerification(user, rawToken);
        
        Assert.NotEqual(rawToken, user.EmailVerificationTokenHash);
    }

    [Fact]
    public void SetPasswordReset_SetsHashAndExpiry()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "" };
        var rawToken= TokenService.GenerateSecureToken();
        
        _authService.SetPasswordReset(user, rawToken);
        
        Assert.False(string.IsNullOrWhiteSpace(user.PasswordResetTokenHash));
        Assert.NotNull(user.PasswordResetTokenExpiry);
        Assert.True(user.PasswordResetTokenExpiry > DateTime.UtcNow.AddMinutes(59));
        Assert.True(user.PasswordResetTokenExpiry <= DateTime.UtcNow.AddHours(2));
    }

    [Fact]
    public async Task FailureAsync_ReturnsExpectedError()
    {
        var error= await _authService.FailureAsync("user@test.com", "invalid_credentials");
        Assert.Equal("invalid_credentials", error);
    }

    [Fact]
    public async Task FailureAsync_RegistersAndDelays()
    {
        // Should complete without throwing even after multiple calls
        await _authService.FailureAsync("brute@test.com", "err");
        await _authService.FailureAsync("brute@test.com", "err");
    }

    [Fact]
    public void ValidateMfa_MultipleMethodsAtOnce_ReturnsFalse()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "", TotpSecret = "JBSWY3DPEHPK3PXP" };
        
        // Providing both totpCode and backupCode simultaneously must be rejected
        var result= _authService.ValidateMfa(user, "123456", "ABCDEF123456", null);
        
        Assert.False(result);
    }

    [Fact]
    public void ValidateMfa_AllThreeMethodsAtOnce_ReturnsFalse()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "" };
        
        var result= _authService.ValidateMfa(user, "123456", "BACKUP", "TOKEN");
        
        Assert.False(result);
    }

    [Fact]
    public void ValidateMfa_NoMethodProvided_ReturnsFalse()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "" };
        
        var result= _authService.ValidateMfa(user, null, null, null);
        
        Assert.False(result);
    }

    [Fact]
    public void ValidateMfa_Totp_NoSecret_ReturnsFalse()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "", TotpSecret = null };
        
        var result= _authService.ValidateMfa(user, "123456", null, null);
        
        Assert.False(result);
    }

    [Fact]
    public void ValidateMfa_Totp_InvalidCode_ReturnsFalse()
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "a@b.com",
            PasswordHash = "",
            TotpSecret = "JBSWY3DPEHPK3PXP"
        };
        
        var result= _authService.ValidateMfa(user, "000000", null, null);
        
        Assert.False(result);
    }

    [Fact]
    public void ValidateMfa_Totp_ValidCode_ThenReplay_ReturnsFalseOnReplay()
    {
        var secretBytes = OtpNet.KeyGeneration.GenerateRandomKey(20);
        var secret = OtpNet.Base32Encoding.ToString(secretBytes);
        var totp = new OtpNet.Totp(secretBytes);
        var code = totp.ComputeTotp();
        
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "a@b.com",
            PasswordHash = "",
            TotpSecret = secret
        };
        
        var first= _authService.ValidateMfa(user, code, null, null);
        var second= _authService.ValidateMfa(user, code, null, null);
        
        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public void ValidateMfa_BackupCode_ValidCode_ReturnsTrueAndConsumesCode()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "" };
        
        var plainCode = "ValidBackup1";
        var hashed= _backupCodeService.HashBackupCode(plainCode);
        user.BackupCodes = new List<string> { hashed };
        
        var result= _authService.ValidateMfa(user, null, plainCode, null);
        
        Assert.True(result);
        Assert.Empty(user.BackupCodes); // code must be consumed
    }

    [Fact]
    public void ValidateMfa_BackupCode_WrongCode_ReturnsFalse()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "" };
        
        var plainCode = "ValidBackup1";
        var hashed= _backupCodeService.HashBackupCode(plainCode);
        user.BackupCodes = new List<string> { hashed };
        
        var result= _authService.ValidateMfa(user, null, "WrongBackup1", null);
        
        Assert.False(result);
        Assert.Single(user.BackupCodes); // code must NOT be consumed
    }

    [Fact]
    public void ValidateMfa_BackupCode_EmptyList_ReturnsFalse()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "", BackupCodes = new List<string>() };
        
        var result= _authService.ValidateMfa(user, null, "AnyCode", null);
        
        Assert.False(result);
    }

    [Fact]
    public void ValidateMfa_BackupCode_CannotBeUsedTwice()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "a@b.com", PasswordHash = "" };
        
        var plainCode = "OneTimeCode1";
        var hashed= _backupCodeService.HashBackupCode(plainCode);
        user.BackupCodes = new List<string> { hashed };
        
        var first= _authService.ValidateMfa(user, null, plainCode, null);
        var second= _authService.ValidateMfa(user, null, plainCode, null);
        
        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public void ValidateMfa_FallbackToken_ValidToken_ReturnsTrue()
    {
        var rawToken= TokenService.GenerateSecureToken();
        var hashed= _tokenService.HashToken(rawToken);
        
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "a@b.com",
            PasswordHash = "",
            TotpFallbackTokenHash = hashed,
            TotpFallbackTokenExpiry = DateTime.UtcNow.AddMinutes(10)
        };
        
        var result= _authService.ValidateMfa(user, null, null, rawToken);
        
        Assert.True(result);
        Assert.Null(user.TotpFallbackTokenHash); // must be consumed
        Assert.Null(user.TotpFallbackTokenExpiry);
    }

    [Fact]
    public void ValidateMfa_FallbackToken_Expired_ReturnsFalse()
    {
        var rawToken= TokenService.GenerateSecureToken();
        var hashed= _tokenService.HashToken(rawToken);
        
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "a@b.com",
            PasswordHash = "",
            TotpFallbackTokenHash = hashed,
            TotpFallbackTokenExpiry = DateTime.UtcNow.AddMinutes(-1) // expired
        };
        
        var result= _authService.ValidateMfa(user, null, null, rawToken);
        
        Assert.False(result);
    }

    [Fact]
    public void ValidateMfa_FallbackToken_WrongToken_ReturnsFalse()
    {
        var rawToken= TokenService.GenerateSecureToken();
        var hashed= _tokenService.HashToken(rawToken);
        
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "a@b.com",
            PasswordHash = "",
            TotpFallbackTokenHash = hashed,
            TotpFallbackTokenExpiry = DateTime.UtcNow.AddMinutes(10)
        };
        
        var result= _authService.ValidateMfa(user, null, null, "wrong-token");
        
        Assert.False(result);
    }

    [Fact]
    public void ValidateMfa_FallbackToken_CannotBeUsedTwice()
    {
        var rawToken= TokenService.GenerateSecureToken();
        var hashed= _tokenService.HashToken(rawToken);
        
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "a@b.com",
            PasswordHash = "",
            TotpFallbackTokenHash = hashed,
            TotpFallbackTokenExpiry = DateTime.UtcNow.AddMinutes(10)
        };
        
        var first= _authService.ValidateMfa(user, null, null, rawToken);
        var second= _authService.ValidateMfa(user, null, null, rawToken);
        
        Assert.True(first);
        Assert.False(second);
    }
}