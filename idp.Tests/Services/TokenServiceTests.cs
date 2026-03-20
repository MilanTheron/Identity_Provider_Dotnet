using System;
using System.Collections.Generic;
using idp.Services;
using idp.Models;
using Xunit;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;

namespace idp.Tests.Services
{
    public class TokenServiceTests
    {
        private readonly TokenService _tokenService;

        public TokenServiceTests()
        {
            // In-memory configuration for testing
            var inMemorySettings = new Dictionary<string, string?>()
            {
                { "Jwt:Key", "supersecretkey123456789012345678" }, // 32 chars = 256 bits
                { "Jwt:Issuer", "TestIssuer" },
                { "Jwt:Audience", "TestAudience" }
            };

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(inMemorySettings)
                .Build();

            _tokenService = new TokenService(configuration);
        }

        [Fact]
        public void GenerateJwtToken_ReturnsNonEmptyString()
        {
            var user = new User { Username = "testuser" };
            var token = _tokenService.GenerateJwtToken(user);

            Assert.False(string.IsNullOrWhiteSpace(token));
        }

        [Fact]
        public void GenerateJwtToken_ParsesCorrectly()
        {
            var user = new User { Username = "testuser" };
            var token = _tokenService.GenerateJwtToken(user);

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            // Basic assertions on token
            Assert.Equal("testuser", jwtToken.Subject);
            Assert.Equal("TestAudience", jwtToken.Audiences.FirstOrDefault());
            Assert.NotNull(jwtToken.Id); // Jti claim exists
        }
    }
}