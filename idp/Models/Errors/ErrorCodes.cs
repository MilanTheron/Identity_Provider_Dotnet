namespace idp.Models.Errors;

public static class ErrorCodes
{
    public const string Unauthorized = "AUTH-001";
    public const string MfaRequired = "AUTH-002";
    public const string InvalidRequest = "REQ-001";
    public const string Conflict = "REQ-002";
    public const string EmailNotVerified = "EMAIL-NOT-VERIFIED";
}