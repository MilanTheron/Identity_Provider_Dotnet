using System.ComponentModel.DataAnnotations;

namespace idp.Models;

public class WebAuthnCredential
{
    [Key]
    public Guid Id { get; set; }
    
    public Guid UserId { get; set; }
    public required byte[] CredentialIdBytes { get; set; }
    public required byte[] PublicKey { get; set; }
    public uint SignCount { get; set; }
}