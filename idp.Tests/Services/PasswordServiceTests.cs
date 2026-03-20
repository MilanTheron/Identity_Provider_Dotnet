using System.Threading.Tasks;
using Xunit;
using idp.Services;

namespace idp.Tests.Services
public class PasswordServiceTests
{
    private class TestPasswordService : PasswordService
    {
        private readonly string[] _pwnedPasswords;

        public TestPasswordService(params string[] pwnedPasswords)
        {
            _pwnedPasswords = pwnedPasswords;
        }

        protected virtual Task<bool> CheckHaveIBeenPwned(string password)
        {
            bool isPwned = _pwnedPasswords != null && Array.Exists(_pwnedPasswords, p => p == password);
            return Task.FromResult(isPwned);
        }
    }

    [Fact]
    public async Task DetectWeakPassword()
    {
        var passwordService = new TestPasswordService("password");

        var weakPassword = "password";            // pwned → weak
        var mediumPassword = "StrongerPa55word";  // fails regex → weak
        var strongPassword = "StrongerPa55word!"; // passes regex → strong

        Assert.True(await passwordService.IsWeak(weakPassword));
        Assert.True(await passwordService.IsWeak(mediumPassword));
        Assert.False(await passwordService.IsWeak(strongPassword));
    }

    [Fact]
    public async Task DetectPwnedPassword()
    {
        var passwordService = new TestPasswordService("123456");

        var pwnedPassword = "123456";   // in breach → weak
        var safePassword = "SafePa55word!"; // not in breach, strong regex → strong

        Assert.True(await passwordService.IsWeak(pwnedPassword));
        Assert.False(await passwordService.IsWeak(safePassword));
    }
    
    [Fact]
    public void VerifyPassword_CorrectPassword_ReturnsTrue()
    {
        string password = "StrongPa55word!";
        string hashed = _passwordService.HashPassword(password);

        bool result = _passwordService.VerifyPassword(password, hashed);

        Assert.True(result);
    }

    [Fact]
    public void VerifyPassword_WrongPassword_ReturnsFalse()
    {
        string password = "StrongPa55word!";
        string wrongPassword = "WrongPa55word!";
        string hashed = _passwordService.HashPassword(password);

        bool result = _passwordService.VerifyPassword(wrongPassword, hashed);

        Assert.False(result);
    }

    [Fact]
    public void VerifyPassword_InvalidHashFormat_ReturnsFalse()
    {
        string password = "StrongPa55word!";
        string invalidHash = "invalidhashwithoutcolon";

        bool result = _passwordService.VerifyPassword(password, invalidHash);

        Assert.False(result);
    }
}