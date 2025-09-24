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
    public string Name { get; set; }
    public string Email { get; set; }
    private string Password { get; set; }
    private string PhoneNumber { get; set; }


    public DateTime CreatedAt { get; set; }

    public DateTime UpdatedAt { get; set; }


    public StatusAccount Status { get; set; }
    public int IDState { get; set; }
    public int StateUserId { get; set; }
    public StateUser State { get; set; }
    public List<Role> Roles { get; set; } = new List<Role>();
}
