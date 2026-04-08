namespace idp.Models;

public class Device
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string DeviceId { get; set; } = null!;
    public string? Location { get; set; }
    public DateTime LastUsed { get; set; }
}