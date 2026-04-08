namespace idp.Controllers.Requests.Totp;

public class TotpSetupResponse
{
    public string Secret { get; set; } = string.Empty;
    public string QrCodeUrl { get; set; } = string.Empty;
    public List<string> BackupCodes { get; set; } = new();
}