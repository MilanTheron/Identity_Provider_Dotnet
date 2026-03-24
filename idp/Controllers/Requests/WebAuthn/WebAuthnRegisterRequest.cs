using System.ComponentModel.DataAnnotations;

namespace idp.Controllers.Requests;

public class WebAuthnRegisterRequest
{
    [Required]
    public string Username { get; set; }
}