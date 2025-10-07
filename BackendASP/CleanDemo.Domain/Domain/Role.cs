namespace CleanDemo.Domain.Domain;

public class Role
{
    public int RoleId { get; set; }
    public required string Name { get; set; }
    public List<User> Users { get; set; } = new List<User>();

}
