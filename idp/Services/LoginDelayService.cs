using System.Collections.Concurrent;

namespace idp.Services;

public class LoginDelayService
{
    private readonly ConcurrentDictionary<string, int> _failures = new();
    private readonly ILogger<LoginDelayService> _logger;

    public LoginDelayService(ILogger<LoginDelayService> logger)
    {
        _logger = logger;
    }

    public int RegisterFailure(string key) => _failures.AddOrUpdate(key, 1, (_, count) => count + 1);

    public void Reset(string key) => _failures.TryRemove(key, out _);

    public Task ApplyDelayAsync(string key)
    {
        var attempts = _failures.GetValueOrDefault(key, 0); 

        var delayMs = Math.Min(5000, (int)Math.Pow(2, attempts) * 150);

        _logger.LogWarning("Auth delay {Delay}ms for {Key}", delayMs, key);

        return Task.Delay(delayMs);
    }
}