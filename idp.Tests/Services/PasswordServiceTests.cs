using idp.Services;
using Microsoft.Extensions.Logging;

namespace idp.Tests.Services;

public class PasswordServiceTests
{
    private class TestPasswordService : PasswordService
    {
        private readonly string[] _pwnedPasswords;

        public TestPasswordService(params string[]? pwnedPasswords)
        {
            if (pwnedPasswords != null)
                _pwnedPasswords = pwnedPasswords;
            else 
                _pwnedPasswords.Append("password");
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
        var weakPassword = "password";            // pwned → weak
        var mediumPassword = "StrongerPa55word";  // fails regex → weak
        var strongPassword = "StrongerPa55word!"; // passes regex → strong

        Assert.True(await TestPasswordService.IsWeak(weakPassword));
        Assert.True(await TestPasswordService.IsWeak(mediumPassword));
        Assert.False(await TestPasswordService.IsWeak(strongPassword));
    }

    [Fact]
    public async Task DetectPwnedPassword()
    {
        var pwnedPassword = "password";   // in breach → weak
        var safePassword = "SafePa55word!"; // not in breach, strong regex → strong

        Assert.True(await TestPasswordService.IsWeak(pwnedPassword));
        Assert.False(await TestPasswordService.IsWeak(safePassword));
    }

    [Fact]
    public void VerifyPassword_CorrectPassword_ReturnsTrue()
    {
        var passwordService = new TestPasswordService("123456");
        
        string password = "StrongPa55word!";
        string hashed = passwordService.HashPassword(password);

        bool result = passwordService.VerifyPassword(password, hashed);

        Assert.True(result);
    }

    [Fact]
    public void VerifyPassword_WrongPassword_ReturnsFalse()
    {
        var passwordService = new TestPasswordService("123456");

        string password = "StrongPa55word!";
        string wrongPassword = "WrongPa55word!";
        string hashed = passwordService.HashPassword(password);

        bool result = passwordService.VerifyPassword(wrongPassword, hashed);

        Assert.False(result);
    }
}