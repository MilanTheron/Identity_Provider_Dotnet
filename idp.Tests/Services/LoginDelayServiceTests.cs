using idp.Services;
using Microsoft.Extensions.Logging.Abstractions;
using System.Diagnostics;

namespace idp.Tests.Services;

public class LoginDelayServiceTests
{
    private readonly LoginDelayService _svc =
        new(NullLogger<LoginDelayService>.Instance);

    [Fact]
    public void RegisterFailure_ReturnsIncrementedCount()
    {
        var count1 = _svc.RegisterFailure("user@test.com");
        var count2 = _svc.RegisterFailure("user@test.com");
        var count3 = _svc.RegisterFailure("user@test.com");

        Assert.Equal(1, count1);
        Assert.Equal(2, count2);
        Assert.Equal(3, count3);
    }

    [Fact]
    public void RegisterFailure_IsolatedPerKey()
    {
        var a = _svc.RegisterFailure("alice@test.com");
        var b = _svc.RegisterFailure("bob@test.com");

        Assert.Equal(1, a);
        Assert.Equal(1, b);
    }

    [Fact]
    public void Reset_ClearsFailureCount()
    {
        _svc.RegisterFailure("user@test.com");
        _svc.RegisterFailure("user@test.com");
        _svc.Reset("user@test.com");

        var count = _svc.RegisterFailure("user@test.com");
        Assert.Equal(1, count);
    }

    [Fact]
    public void Reset_UnknownKey_DoesNotThrow()
    {
        var ex = Record.Exception(() => _svc.Reset("nobody@test.com"));
        Assert.Null(ex);
    }

    [Fact]
    public async Task ApplyDelayAsync_NoFailures_IsAbout150ms()
    {
        var sw = Stopwatch.StartNew();
        await _svc.ApplyDelayAsync("fresh@test.com");
        sw.Stop();

        Assert.InRange(sw.ElapsedMilliseconds, 100, 400);
    }

    [Fact]
    public async Task ApplyDelayAsync_ManyFailures_CapsAt5000ms()
    {
        for (var i = 0; i < 10; i++)
            _svc.RegisterFailure("spammer@test.com");
        
        var sw = Stopwatch.StartNew();
        await _svc.ApplyDelayAsync("spammer@test.com");
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds <= 6000,
            $"Delay was {sw.ElapsedMilliseconds} ms, expected ≤ 6000 ms");
    }

    [Fact]
    public async Task ApplyDelayAsync_GrowsWithFailures()
    {
        _svc.RegisterFailure("growing@test.com");

        var sw = Stopwatch.StartNew();
        await _svc.ApplyDelayAsync("growing@test.com");
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds >= 200,
            $"Expected ≥ 200 ms for 1 failure, got {sw.ElapsedMilliseconds} ms");
    }
}