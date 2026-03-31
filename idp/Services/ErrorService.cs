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