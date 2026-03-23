using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class WebAuthnCredential
{
    [Key]
    public int Id { get; set; }
    
    public string UserId { get; set; }
    public byte[] CredentialIdBytes { get; set; }
    public byte[] PublicKey { get; set; }
    public uint SignCount { get; set; }
}