namespace idp.Models.Errors;

public static class ErrorCodes
{
    public const string Unauthorized = "AUTH-001";
    public const string MfaRequired = "AUTH-002";
    public const string InvalidRequest = "REQ-001";
    public const string Conflict = "REQ-002";
    public const string InvalidCredentials = "INVALID-CREDENTIALS";
    public const string InvalidCode = "INVALID-CODE";
    public const string WeakPassword = "WEAK-PASSWORD";
    public const string EmailNotVerified = "EMAIL-NOT-VERIFIED";
}