namespace idp.Models;

public class OAuthClient
{
    public int Id { get; set; }
    public required string ClientId { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public bool RequirePkce { get; set; } = true;
}