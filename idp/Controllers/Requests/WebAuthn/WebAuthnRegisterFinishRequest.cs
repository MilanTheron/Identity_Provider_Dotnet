using Fido2NetLib;

namespace idp.Controllers.Requests.WebAuthn;

public class WebAuthnRegisterFinishRequest
{
    public required AuthenticatorAttestationRawResponse ClientResponse { get; set; }
}