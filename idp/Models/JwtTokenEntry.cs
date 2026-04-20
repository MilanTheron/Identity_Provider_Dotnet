using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class JwtTokenEntry
{
    [Key]
    [MaxLength(128)]
    public string Jti { get; set; } = null!;
    public DateTime Expiry { get; set; }
}