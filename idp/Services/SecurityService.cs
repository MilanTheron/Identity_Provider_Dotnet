using System.Collections.Concurrent;

namespace idp.Services;

public class SecurityService
{
    private static readonly ConcurrentDictionary<string, (int count, DateTime resetTime, DateTime lastAttempt)> LoginAttempts = new();
    private const int MaxLoginAttempts = 10;
    private const int RateLimitWindowMinutes = 1;
    private const int AccountLockoutMinutes = 5;
    private const int FailedAttemptsBeforeLockout = 5;
    private const int TimeSinceLastAttemptLockout = 5; // seconds

    public bool IsRateLimited(string clientIp)
    {
        if (string.IsNullOrEmpty(clientIp))
            return true;

        var now = DateTime.UtcNow;

        var attempts = LoginAttempts.AddOrUpdate(
            clientIp,
            (1, now.AddMinutes(RateLimitWindowMinutes), now),
            (_, existing) =>
            {
                if (now >= existing.resetTime)
                    return (1, now.AddMinutes(RateLimitWindowMinutes), now); // reset window
                return (existing.count + 1, existing.resetTime, now);
            }
        );

        // Check rate limit AFTER ensuring state is correct
        return attempts.count > MaxLoginAttempts && now < attempts.resetTime;
    }

    public bool CanAttemptLogin(string clientIp, out TimeSpan? waitTime)
    {
        waitTime = null;

        if (string.IsNullOrEmpty(clientIp))
            return false;

        if (LoginAttempts.TryGetValue(clientIp, out var attempts))
        {
            var timeSinceLastAttempt = DateTime.UtcNow - attempts.lastAttempt;

            if (timeSinceLastAttempt.TotalSeconds < TimeSinceLastAttemptLockout)
            {
                waitTime = TimeSpan.FromSeconds(TimeSinceLastAttemptLockout) - timeSinceLastAttempt;
                return false;
            }
        }

        return true;
    }
    
    public Task<bool> ValidateJtiAsync(string jti)
    {
        if (string.IsNullOrEmpty(jti))
            return Task.FromResult(false);

        if (!ValidJtis.TryGetValue(jti, out var expiry))
            return Task.FromResult(false);

        if (DateTime.UtcNow > expiry)
        {
            // cleanup expired token
            ValidJtis.TryRemove(jti, out _);
            return Task.FromResult(false);
        }

        return Task.FromResult(true);
    }
    
    public Task StoreJtiAsync(string jti, DateTime expiry)
    {
        if (string.IsNullOrEmpty(jti))
            return Task.CompletedTask;

        ValidJtis[jti] = expiry;
        return Task.CompletedTask;
    }
    
    public Task RevokeJtiAsync(string jti)
    {
        if (string.IsNullOrEmpty(jti))
            return Task.CompletedTask;

        ValidJtis.TryRemove(jti, out _);
        return Task.CompletedTask;
    }

    public static void RecordFailedAttempt(string clientIp)
    {
        if (string.IsNullOrEmpty(clientIp))
            return;

        var now = DateTime.UtcNow;

        LoginAttempts.AddOrUpdate(
            clientIp,
            (1, now.AddMinutes(RateLimitWindowMinutes), now),
            (_, existing) => (existing.count + 1, existing.resetTime, now)
        );
    }

    public void ClearFailedAttempts(string clientIp)
    {
        if (string.IsNullOrEmpty(clientIp))
            return;

        LoginAttempts.TryRemove(clientIp, out _);
    }

    public static TimeSpan GetLockoutDuration() => TimeSpan.FromMinutes(AccountLockoutMinutes);

    public static int GetFailedAttemptsThreshold() => FailedAttemptsBeforeLockout;
    
    private static readonly ConcurrentDictionary<string, DateTime> ValidJtis = new();
}