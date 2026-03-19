using System.Collections.Concurrent;

namespace idp.Services;

public class SecurityService
{
    private static readonly ConcurrentDictionary<string, (int count, DateTime resetTime)> LoginAttempts = new();
    private const int MaxLoginAttempts = 10;
    private const int RateLimitWindowMinutes = 1;
    private const int AccountLockoutMinutes = 15;
    private const int FailedAttemptsBeforeLockout = 5;
    private const int TimeSinceLastAttemptLockout = 5; // seconds

    public bool IsRateLimited(string clientIp)
    {
        if (string.IsNullOrEmpty(clientIp))
            return true;

        var attempts = LoginAttempts.GetOrAdd(clientIp, (0, DateTime.UtcNow.AddMinutes(RateLimitWindowMinutes)));

        if (attempts.count >= MaxLoginAttempts && DateTime.UtcNow < attempts.resetTime)
            return true;

        // Reset if window has passed
        if (DateTime.UtcNow >= attempts.resetTime)
        {
            LoginAttempts.TryUpdate(clientIp, (0, DateTime.UtcNow.AddMinutes(RateLimitWindowMinutes)), attempts);
        }

        return false;
    }

    public bool CanAttemptLogin(string clientIp, out TimeSpan? waitTime)
    {
        waitTime = null;

        if (string.IsNullOrEmpty(clientIp))
            return false;

        if (LoginAttempts.TryGetValue(clientIp, out var attempts))
        {
            // Calculate time since last attempt
            var lastAttemptTime = attempts.resetTime.AddMinutes(-RateLimitWindowMinutes);
            var timeSinceLastAttempt = DateTime.UtcNow - lastAttemptTime;

            if (timeSinceLastAttempt.TotalSeconds < TimeSinceLastAttemptLockout)
            {
                waitTime = TimeSpan.FromSeconds(TimeSinceLastAttemptLockout) - timeSinceLastAttempt;
                return false; // Too soon, reject attempt
            }
        }

        return true; // Allowed
    }

    public void RecordFailedAttempt(string clientIp)
    {
        if (string.IsNullOrEmpty(clientIp))
            return;

        var attempts = LoginAttempts.GetOrAdd(clientIp, (0, DateTime.UtcNow.AddMinutes(RateLimitWindowMinutes)));
        LoginAttempts[clientIp] = (attempts.count + 1, attempts.resetTime);
    }

    public void ClearFailedAttempts(string clientIp)
    {
        if (string.IsNullOrEmpty(clientIp))
            return;

        LoginAttempts.TryRemove(clientIp, out _);
    }

    public static TimeSpan GetLockoutDuration() => TimeSpan.FromMinutes(AccountLockoutMinutes);

    public static int GetFailedAttemptsThreshold() => FailedAttemptsBeforeLockout;
}

