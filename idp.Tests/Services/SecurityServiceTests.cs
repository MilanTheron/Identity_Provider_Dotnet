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