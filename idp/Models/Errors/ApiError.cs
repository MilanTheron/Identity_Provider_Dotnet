namespace idp.Models.Errors;

public class ApiError
{
    public string Code { get; set; } = default!;
    public string TraceId { get; set; } = string.Empty;
}