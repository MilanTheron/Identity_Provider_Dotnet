using idp.Models;
using OtpNet;
using System.Security.Cryptography;

namespace idp.Services;
public class AuthService
{
    private readonly TokenService _tokenService;
    private readonly BackupCodeService _backupCodeService;
    private readonly LoginDelayService _delayService;

    public AuthService(TokenService tokenService, BackupCodeService backupCodeService, LoginDelayService delayService)
    {
        _tokenService = tokenService;
        _backupCodeService = backupCodeService;
        _delayService = delayService;
    }

    public void SetEmailVerification(User user, string rawToken)
    {
        user.EmailVerificationTokenHash = _tokenService.HashToken(rawToken);
        user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24);
    }

    public void SetPasswordReset(User user, string rawToken)
    {
        user.PasswordResetTokenHash = _tokenService.HashToken(rawToken);
        user.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(1);
    }
    
    public async Task<string> FailureAsync(string key, string error)
    {
        _delayService.RegisterFailure(key);
        await _delayService.ApplyDelayAsync(key);
        return error;
    }

    public bool ValidateMfa(User user, string? totpCode, string? backupCode, string? fallbackToken)
    {
        int methodsUsed = 0;

        if (!string.IsNullOrWhiteSpace(totpCode)) methodsUsed++;
        if (!string.IsNullOrWhiteSpace(backupCode)) methodsUsed++;
        if (!string.IsNullOrWhiteSpace(fallbackToken)) methodsUsed++;

        if (methodsUsed > 1)
            return false;

        // ---- TOTP ----
        if (!string.IsNullOrWhiteSpace(totpCode))
        {
            if (string.IsNullOrEmpty(user.TotpSecret))
                return false;

            try
            {
                var secretBytes = Base32Encoding.ToBytes(user.TotpSecret);
                var totp = new Totp(secretBytes);

                var window = new VerificationWindow(previous: 1, future: 1);
                var code = totpCode.Trim();

                if (!totp.VerifyTotp(code, out var step, window))
                    return false;

                if (user.LastTotpStepUsed == step)
                    return false;

                user.LastTotpStepUsed = step;
                return true;
            }
            catch
            {
                return false;
            }
        }

        // ---- fallback ----
        if (!string.IsNullOrEmpty(fallbackToken) && !string.IsNullOrEmpty(user.TotpFallbackTokenHash))
        {
            if (user.TotpFallbackTokenExpiry < DateTime.UtcNow)
                return false;

            var hashed = _tokenService.HashToken(fallbackToken);

            if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(user.TotpFallbackTokenHash),
                Convert.FromBase64String(hashed)))
                return false;

            user.TotpFallbackTokenHash = null;
            user.TotpFallbackTokenExpiry = null;
            return true;
        }

        // ---- backup ----
        if (string.IsNullOrWhiteSpace(backupCode) || user.BackupCodes?.Count == 0)
            return false;

        var hashedInput = _backupCodeService.HashBackupCode(backupCode.Trim());

        var match = user.BackupCodes.FirstOrDefault(stored =>
            CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(stored),
                Convert.FromBase64String(hashedInput)
            ));

        if (match == null)
            return false;

        user.BackupCodes.Remove(match);
        return true;
    }
}