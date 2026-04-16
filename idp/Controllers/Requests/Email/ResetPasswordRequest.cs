namespace idp.Controllers.Requests.Email;

public class ResetPasswordRequest
{
    public string? Token { get; set; }
    public string? UserId { get; set; }
    public string? NewPassword { get; set; }
}