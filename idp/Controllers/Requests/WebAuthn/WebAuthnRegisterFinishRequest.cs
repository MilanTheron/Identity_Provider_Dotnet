using Fido2NetLib;

namespace idp.Controllers.Requests;

public class WebAuthnRegisterFinishRequest
{
    public string Username { get; set; }
    public AuthenticatorAttestationRawResponse ClientResponse { get; set; }
}