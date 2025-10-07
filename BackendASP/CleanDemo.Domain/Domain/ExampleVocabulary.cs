namespace CleanDemo.Domain.Domain;

public class ExampleVocabulary
{
    public int ExampleVocabularyId { get; set; }
    public required string Example { get; set; }

    public int VocabId { get; set; }
    public Vocab? Vocab { get; set; }




}
