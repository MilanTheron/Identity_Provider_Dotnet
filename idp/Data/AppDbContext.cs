using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Microsoft.EntityFrameworkCore.ChangeTracking; // Needed for ValueComparer
using System.Text.Json;
using idp.Models;

namespace idp.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
    public DbSet<Device> Devices { get; set; }
    public DbSet<WebAuthnCredential> WebAuthnCredentials { get; set; }
    public DbSet<OAuthClient> OAuthClients { get; set; }
    public DbSet<AuthorizationCode> AuthorizationCodes { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var redirectUrisConverter = new ValueConverter<List<string>, string>(
            v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
            v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null)!
        );

        var redirectUrisComparer = new ValueComparer<List<string>>(
            (c1, c2) => c1.SequenceEqual(c2),
            c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
            c => c.ToList()
        );

        modelBuilder.Entity<OAuthClient>()
            .Property(c => c.RedirectUris)
            .HasConversion(redirectUrisConverter)
            .Metadata.SetValueComparer(redirectUrisComparer);

        base.OnModelCreating(modelBuilder);
    }
}