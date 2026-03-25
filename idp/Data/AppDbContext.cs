using Microsoft.EntityFrameworkCore;
using idp.Models;

namespace idp.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
    public DbSet<WebAuthnCredential> WebAuthnCredentials { get; set; }
    public DbSet<AuthorizationCode>  AuthorizationCodes { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }
}
