using System.Text.Json;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

public class OAuthClient
{
    public int Id { get; set; }
    public required string ClientId { get; set; }
    public string RedirectUrisJson { get; set; } = "[]";
    public bool RequirePkce { get; set; } = true;

    [NotMapped]
    public List<string> RedirectUris
    {
        get => JsonSerializer.Deserialize<List<string>>(RedirectUrisJson) ?? new List<string>();
        set => RedirectUrisJson = JsonSerializer.Serialize(value);
    }
}