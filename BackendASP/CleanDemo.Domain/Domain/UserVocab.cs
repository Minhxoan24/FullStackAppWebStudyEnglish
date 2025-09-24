namespace CleanDemo.Domain.Domain;

public class UserVocab
{
    public int UserVocabId { get; set; }
    public int UserId { get; set; }
    public User? User { get; set; }
    public int VocabId { get; set; }
    public Vocab? Vocab { get; set; }
    public int Attempts { get; set; } = 0;
    public bool IsMastered { get; set; } = false;
}
