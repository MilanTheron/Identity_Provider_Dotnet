using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace idp.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ErrorController : ControllerBase
    {
        [AllowAnonymous]
        [Route("/Error")]
        public IActionResult HandleError()
        {
            return Problem(
                title: "An unexpected error occurred.",
                statusCode: StatusCodes.Status500InternalServerError
            );
        }

        [AllowAnonymous]
        [Route("/Error/{statusCode}")]
        public IActionResult HandleStatusCode(int statusCode)
        {
            return Problem(
                title: $"Request failed with status code {statusCode}",
                statusCode: statusCode
            );
        }
    }
}