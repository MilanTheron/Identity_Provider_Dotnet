using idp.Models.Errors;
using Microsoft.AspNetCore.Mvc;

namespace idp.Services;

public class ErrorService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public ErrorService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    
    public string Translate(string code)
    {
        return code switch
        {
            ErrorCodes.InvalidRequest => "Invalid request",
            ErrorCodes.InvalidCredentials => "Invalid credentials",
            ErrorCodes.Unauthorized => "Unauthorized",
            ErrorCodes.MfaRequired => "MFA required",
            ErrorCodes.Conflict => "Conflict",
            ErrorCodes.WeakPassword => "Password too weak",
            ErrorCodes.EmailNotVerified => "Email not verified",
            
            _ => "Unknown error"
        };
    }

    public IActionResult AuthError(string code)
    {
        return new UnauthorizedObjectResult(new ApiError
        {
            Code = code,
            TraceId = _httpContextAccessor.HttpContext?.TraceIdentifier
        });
    }

    public IActionResult BadReq(string code)
    {
        return new BadRequestObjectResult(new ApiError
        {
            Code = code,
            TraceId = _httpContextAccessor.HttpContext?.TraceIdentifier
        });
    }

    public IActionResult ConflictError(string code)
    {
        return new ConflictObjectResult(new ApiError
        {
            Code = code,
            TraceId = _httpContextAccessor.HttpContext?.TraceIdentifier
        });
    }
}