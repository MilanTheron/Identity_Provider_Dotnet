using Fido2NetLib;

namespace idp.Controllers.Requests.WebAuthn;

public class WebAuthnLoginFinishRequest
{
    public required AuthenticatorAssertionRawResponse ClientResponse { get; set; }
}