namespace idp.Controllers.Requests.Email;

public class VerifyEmailRequest
{
    public string? UserId { get; set; }
    public string? Token { get; set; }
}