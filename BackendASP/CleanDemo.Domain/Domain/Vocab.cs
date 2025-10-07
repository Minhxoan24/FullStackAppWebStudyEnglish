namespace CleanDemo.Domain.Domain;

public class Vocab
{
    public int VocabId { get; set; }
    public required string Language { get; set; }
    public required string Word { get; set; }
    public required string TypeWord { get; set; }
    public required string MeaningVN { get; set; }
    public required string MeaningEN { get; set; }
    public required string ImageUrl { get; set; }
    public required string UsageNotes { get; set; }

    public required string Pronunciation { get; set; }
    public required string AudioUrl { get; set; }


    public required string Ranking { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdateAt { get; set; }
    public int TopicId { get; set; }
    public Topic? Topic { get; set; }


    public List<ExampleVocabulary>? ExampleVocabularies { get; set; } = new List<ExampleVocabulary>();
}