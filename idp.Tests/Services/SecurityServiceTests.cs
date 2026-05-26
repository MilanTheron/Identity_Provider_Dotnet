using idp.Data;
using idp.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;

namespace idp.Tests.Services;

public class SecurityServieTests
{
    private readonly AppDbContext _dbContext;
    
    public SecurityServieTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase("TestDb")
            .Options;
        
        _dbContext = new AppDbContext(options);
    }
    
    private static string NewJti()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return WebEncoders.Base64UrlEncode(bytes);
    }
 
    [Fact]
    public async Task ValidateJti_ValidNotExpired_ReturnsTrue()
    {
        var jti = NewJti();
        
        await SecurityService.StoreJtiAsync(_dbContext, jti, DateTime.UtcNow.AddMinutes(30));
        
        Assert.True(await SecurityService.ValidateJtiAsync(_dbContext, jti));
    }
 
    [Fact]
    public async Task ValidateJti_Expired_ReturnsFalseAndRemovesEntry()
    {
        var jti = NewJti();
        
        await SecurityService.StoreJtiAsync(_dbContext, jti, DateTime.UtcNow.AddMinutes(-1));
        
        var result = await SecurityService.ValidateJtiAsync(_dbContext, jti);
        
        Assert.False(result);
        
        var exists = await _dbContext.JwtTokens.AnyAsync(x => x.Jti == jti);
        Assert.False(exists);
    }
 
    [Fact]
    public async Task ValidateJti_UnknownJti_ReturnsFalse()
    {
        var result = await SecurityService.ValidateJtiAsync(_dbContext, "nonexistent-jti");
        
        Assert.False(result);
    }
 
    [Fact]
    public async Task RevokeJti_ExistingJti_RemovesEntry()
    {
        var jti = NewJti();
        
        await SecurityService.StoreJtiAsync(_dbContext, jti, DateTime.UtcNow.AddMinutes(30));
        await SecurityService.RevokeJtiAsync(_dbContext, jti);
        
        Assert.False(await SecurityService.ValidateJtiAsync(_dbContext, jti));
    }
 
    [Fact]
    public async Task RevokeJti_UnknownJti_DoesNotThrow()
    {
        var ex = await Record.ExceptionAsync(() =>
            SecurityService.RevokeJtiAsync(_dbContext, "does-not-exist"));
        
        Assert.Null(ex);
    }
 
    [Fact]
    public async Task StoreJti_PersistsCorrectExpiry()
    {
        var jti = NewJti();
        var expiry = DateTime.UtcNow.AddMinutes(30);
        
        await SecurityService.StoreJtiAsync(_dbContext, jti, expiry);
        
        var entry = await _dbContext.JwtTokens.FirstOrDefaultAsync(x => x.Jti == jti);
        Assert.NotNull(entry);
        Assert.Equal(expiry, entry!.Expiry, TimeSpan.FromSeconds(1));
    }
    
    [Fact]
    public async Task GenerateJtiToken_ReturnTrue()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var jti = WebEncoders.Base64UrlEncode(bytes);
        var expiry = DateTime.UtcNow.AddMinutes(30);
        
        await SecurityService.StoreJtiAsync(_dbContext, jti, expiry);
        
        Assert.True(await SecurityService.ValidateJtiAsync(_dbContext, jti));
    }
    
    [Fact]
    public async Task RevokeJtiToken_ReturnFalse()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var jti = WebEncoders.Base64UrlEncode(bytes);
        var expiry = DateTime.UtcNow.AddMinutes(-30);
        
        await SecurityService.StoreJtiAsync(_dbContext, jti, expiry);
    }
}