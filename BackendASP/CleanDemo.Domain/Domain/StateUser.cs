namespace CleanDemo.Domain.Domain;

public class StateUser
{
    public int StateUserId { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }

    public User User { get; set; }
}