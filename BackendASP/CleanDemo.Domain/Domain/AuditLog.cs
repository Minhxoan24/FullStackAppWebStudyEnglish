namespace CleanDemo.Domain.Domain;

public class AuditLog
{
    public int AuditLogId { get; set; }
    public int UserId { get; set; }
    public string Action { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
