namespace CleanDemo.Domain.Domain;

public class PasswordResetToken
{
    public int Id { get; set; }
    public required string Token { get; set; }
    public int UserId { get; set; }
    public User? User { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
