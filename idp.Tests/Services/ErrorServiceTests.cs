using idp.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using idp.Models.Errors;

namespace idp.Tests.Services;

public class ErrorServiceTests
{
    private static ErrorService Build(string? traceId = "trace-123")
    {
        var ctx = new DefaultHttpContext();
        if (traceId != null)
            ctx.TraceIdentifier = traceId;

        var accessor = new HttpContextAccessor { HttpContext = ctx };
        return new ErrorService(accessor);
    }
    
    [Theory]
    [InlineData(ErrorCodes.InvalidRequest, "Invalid request")]
    [InlineData(ErrorCodes.InvalidCredentials, "Invalid credentials")]
    [InlineData(ErrorCodes.Unauthorized, "Unauthorized")]
    [InlineData(ErrorCodes.MfaRequired, "MFA required")]
    [InlineData(ErrorCodes.Conflict, "Conflict")]
    [InlineData(ErrorCodes.WeakPassword, "Password too weak")]
    [InlineData(ErrorCodes.EmailNotVerified, "Email not verified")]
    public void Translate_KnownCode_ReturnsHumanReadableString(string code, string expected)
    {
        var svc = Build();
        Assert.Equal(expected, svc.Translate(code));
    }

    [Fact]
    public void Translate_UnknownCode_ReturnsCodeAsIs()
    {
        var svc = Build();
        Assert.Equal("some_unknown_code", svc.Translate("some_unknown_code"));
    }
    
    [Fact]
    public void AuthError_Returns401WithCodeAndTraceId()
    {
        var svc = Build("trace-abc");
        var result = svc.AuthError(ErrorCodes.Unauthorized);

        var obj = Assert.IsType<UnauthorizedObjectResult>(result);
        var body = Assert.IsType<ApiError>(obj.Value);
        Assert.Equal(ErrorCodes.Unauthorized, body.Code);
        Assert.Equal("trace-abc", body.TraceId);
    }

    [Fact]
    public void BadReq_Returns400WithCodeAndTraceId()
    {
        var svc = Build("trace-xyz");
        var result = svc.BadReq(ErrorCodes.InvalidRequest);

        var obj = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ApiError>(obj.Value);
        Assert.Equal(ErrorCodes.InvalidRequest, body.Code);
        Assert.Equal("trace-xyz", body.TraceId);
    }

    [Fact]
    public void ConflictError_Returns409WithCodeAndTraceId()
    {
        var svc = Build("trace-456");
        var result = svc.ConflictError(ErrorCodes.Conflict);

        var obj = Assert.IsType<ConflictObjectResult>(result);
        var body = Assert.IsType<ApiError>(obj.Value);
        Assert.Equal(ErrorCodes.Conflict, body.Code);
        Assert.Equal("trace-456", body.TraceId);
    }

    [Fact]
    public void AllMethods_NullHttpContext_TraceIdIsNull()
    {
        var accessor = new HttpContextAccessor { HttpContext = null };
        var svc = new ErrorService(accessor);

        var auth = Assert.IsType<UnauthorizedObjectResult>(svc.AuthError(ErrorCodes.Unauthorized));
        var bad = Assert.IsType<BadRequestObjectResult>(svc.BadReq(ErrorCodes.InvalidRequest));
        var conflict = Assert.IsType<ConflictObjectResult>(svc.ConflictError(ErrorCodes.Conflict));

        Assert.Null(((ApiError)auth.Value!).TraceId);
        Assert.Null(((ApiError)bad.Value!).TraceId);
        Assert.Null(((ApiError)conflict.Value!).TraceId);
    }
}