using idp.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace idp.Tests.Services;

public class BackupCodeServiceTests
{
    private readonly BackupCodeService _backupCodeService = new BackupCodeService(NullLogger<BackupCodeService>.Instance);

    [Fact]
    public void GenerateBackupCodes_ReturnsCorrectCountAndLength()
    {
        var result = _backupCodeService.GenerateBackupCodes(5, 8);

        Assert.NotNull(result);
        Assert.Equal(5, result.Count);
        Assert.All(result, code => Assert.Equal(8, code.Length));
    }

    [Fact]
    public void GenerateBackupCodes_ReturnsUniqueCodes()
    {
        var codes = _backupCodeService.GenerateBackupCodes(100, 12);
        var uniqueCodes = codes.Distinct().ToList();
        
        Assert.Equal(codes.Count, uniqueCodes.Count);
    }

    [Fact]
    public void GenerateRandomCode_ProducesOnlyValidCharacters()
    {
        const string validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var code = _backupCodeService.GenerateBackupCodes(1, 50).First();
        
        Assert.All(code, c => Assert.Contains(c, validChars));
    }

    [Fact]
    public void HashBackupCode_ReturnsNonEmptyString()
    {
        var code = "MyTestCode123";
        var hash = _backupCodeService.HashBackupCode(code);

        Assert.False(string.IsNullOrWhiteSpace(hash));
    }

    [Fact]
    public void HashBackupCode_HashFormatContainsSaltAndHash()
    {
        var code = "MyTestCode123";
        var hash = _backupCodeService.HashBackupCode(code);

        var parts = hash.Split(':');
        Assert.Equal(2, parts.Length);
        Assert.False(string.IsNullOrWhiteSpace(parts[0])); // Salt
        Assert.False(string.IsNullOrWhiteSpace(parts[1])); // Hash
    }

    [Fact]
    public void HashBackupCode_SameCodeReturnsSameHashWithSameSalt()
    {
        var code = "ConsistentCode";
        var hash1 = _backupCodeService.HashBackupCode(code);
        var hash2 = _backupCodeService.HashBackupCode(code);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void GenerateBackupCodes_RandomnessTest()
    {
        var codes1 = _backupCodeService.GenerateBackupCodes(50, 12);
        var codes2 = _backupCodeService.GenerateBackupCodes(50, 12);

        // Not likely to produce the same sequence
        Assert.NotEqual(codes1, codes2);
    }
}