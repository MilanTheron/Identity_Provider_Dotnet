using System.Text.Json;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class OAuthClient
{
    public int Id { get; set; }
    [MaxLength(20)]
    public string ClientId { get; set; } = string.Empty;
    [MaxLength(2048)]
    public string RedirectUrisJson { get; set; } = "[]";
    public bool RequirePkce { get; set; } = true;
    [MaxLength(2048)]
    public string ClientSecret { get; set; } = string.Empty;
    
    public List<String> AllowedScopes { get; set; } = new List<String>();

    [NotMapped]
    public List<string> RedirectUris
    {
        get => JsonSerializer.Deserialize<List<string>>(RedirectUrisJson) ?? new List<string>();
        set => RedirectUrisJson = JsonSerializer.Serialize(value);
    }
}