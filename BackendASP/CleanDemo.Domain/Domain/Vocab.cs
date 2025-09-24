namespace CleanDemo.Domain.Domain;

public class Vocab
{
    public int VocabId { get; set; }
    public string Language { get; set; }
    public string Word { get; set; }
    public string TypeWord { get; set; }
    public string MeaningVN { get; set; }
    public string MeaningEN { get; set; }
    public string ImageUrl { get; set; }
    public string UsageNotes { get; set; }

    public string Pronunciation { get; set; }
    public string AudioUrl { get; set; }


    public string Ranking { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdateAt { get; set; }
    public int TopicId { get; set; }
    public Topic? Topic { get; set; }


    public List<ExampleVocabulary>? ExampleVocabularies { get; set; } = new List<ExampleVocabulary>();






}