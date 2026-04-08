namespace idp.Controllers.Requests;

public class LoginRequest
{
    public string? Email { get; set; }
    public string? Password { get; set; }
    public string? TotpCode { get; set; }
    public string? BackupCode { get; set; }
    public string? Scope { get; set; }
    public string? TotpFallbackToken { get; set; }
}

