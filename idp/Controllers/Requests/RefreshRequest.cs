namespace idp.Models;

public class RefreshRequest
{
    public string RefreshToken { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
}