using Fido2NetLib;

namespace idp.Controllers.Requests.WebAuthn;

public class WebAuthnRegisterFinishRequest
{
    public required string Username { get; set; }
    public required AuthenticatorAttestationRawResponse ClientResponse { get; set; }
}