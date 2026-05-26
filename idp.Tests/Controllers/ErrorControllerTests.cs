using idp.Controllers;
using Microsoft.AspNetCore.Mvc;

namespace idp.Tests.Controllers;

public class ErrorControllerTests
{
    [Fact]
    public void HandleError_Returns500Problem()
    {
        var ctrl = new ErrorController();

        var result = ctrl.HandleError();

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(500, obj.StatusCode);
        Assert.NotNull(obj.Value);
    }

    [Fact]
    public void HandleStatusCode_ReturnsGivenStatusCode()
    {
        var ctrl = new ErrorController();

        var result = ctrl.HandleStatusCode(404);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(404, obj.StatusCode);
    }
}

