namespace CleanDemo.Domain.Domain;

public class Topic
{
    public int TopicId { get; set; }
    public required string Name { get; set; }
    public required string Description { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public List<Vocab>? Vocabs { get; set; } = new List<Vocab>();

}
