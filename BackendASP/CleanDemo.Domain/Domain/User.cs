namespace CleanDemo.Domain.Domain;

public enum StatusAccount
{
    Active,
    Inactive,
    Suspended
}

public class User
{
    public int UserId { get; set; }
    public string SureName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Name => $"{SureName} {LastName}".Trim(); // Computed property
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty; // Đổi tên và public
    public string PhoneNumber { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public StatusAccount Status { get; set; } = StatusAccount.Active;
    public List<Role> Roles { get; set; } = new List<Role>();


    public void SetPassword(string password)
    {
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(password);
    }

    public bool VerifyPassword(string password)
    {
        return BCrypt.Net.BCrypt.Verify(password, PasswordHash);
    }
}
