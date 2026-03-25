using Fido2NetLib;

namespace idp.Controllers.Requests.WebAuthn;

public class WebAuthnLoginFinishRequest
{
    public required string Username { get; set; }
    public required string CredentialId { get; set; }
    public required AuthenticatorAssertionRawResponse ClientResponse { get; set; }
}