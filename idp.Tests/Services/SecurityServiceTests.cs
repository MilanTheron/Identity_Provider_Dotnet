using System;
using System.Threading;
using idp.Services;
using System.Linq;
using Xunit;

namespace idp.Tests.Services;

public class SecurityServiceTests
{
    private readonly SecurityService _service = new();

    [Fact]
    public void IsRateLimited_ReturnsTrue_WhenIpIsNull()
    {
        var result = _service.IsRateLimited(null);

        Assert.True(result);
    }

    [Fact]
    public void IsRateLimited_ReturnsFalse_ForNewIp()
    {
        var result = _service.IsRateLimited("127.0.0.1");

        Assert.False(result);
    }

    [Fact]
    public void RecordFailedAttempt_IncrementsAttempts()
    {
        var ip = "192.168.1.1";

        for (int i = 0; i < 10; i++)
        {
            _service.RecordFailedAttempt(ip);
        }

        var result = _service.IsRateLimited(ip);

        Assert.True(result);
    }

    [Fact]
    public void ClearFailedAttempts_RemovesTracking()
    {
        var ip = "10.0.0.1";

        _service.RecordFailedAttempt(ip);
        _service.ClearFailedAttempts(ip);

        var result = _service.IsRateLimited(ip);

        Assert.False(result);
    }

    [Fact]
    public void CanAttemptLogin_ReturnsFalse_WhenTooFast()
    {
        var ip = "fast-ip";

        _service.RecordFailedAttempt(ip);

        var allowed = _service.CanAttemptLogin(ip, out var waitTime);

        Assert.False(allowed);
        Assert.NotNull(waitTime);
    }

    [Fact]
    public void CanAttemptLogin_ReturnsTrue_AfterDelay()
    {
        var ip = "slow-ip";

        _service.RecordFailedAttempt(ip);

        Thread.Sleep(6000); // > TimeSinceLastAttemptLockout

        var allowed = _service.CanAttemptLogin(ip, out var waitTime);

        Assert.True(allowed);
        Assert.Null(waitTime);
    }

    [Fact]
    public void GetLockoutDuration_Returns15Minutes()
    {
        var duration = SecurityService.GetLockoutDuration();

        Assert.Equal(TimeSpan.FromMinutes(15), duration);
    }

    [Fact]
    public void GetFailedAttemptsThreshold_Returns5()
    {
        var threshold = SecurityService.GetFailedAttemptsThreshold();

        Assert.Equal(5, threshold);
    }
}