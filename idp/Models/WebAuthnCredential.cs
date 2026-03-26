using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class WebAuthnCredential
{
    [Key]
    public int Id { get; set; }
    
    public int UserId { get; set; }
    public required byte[] CredentialIdBytes { get; set; }
    public required byte[] PublicKey { get; set; }
    public uint SignCount { get; set; }
}