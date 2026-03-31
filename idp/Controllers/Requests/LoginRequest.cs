namespace idp.Controllers.Requests;

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string TotpCode { get; set; } = string.Empty;
    public string BackupCode { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
}

