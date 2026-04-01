namespace idp.Models.Errors;

public class ApiError
{
    public string Code { get; set; } = string.Empty;
    public string TraceId { get; set; } = string.Empty;
}