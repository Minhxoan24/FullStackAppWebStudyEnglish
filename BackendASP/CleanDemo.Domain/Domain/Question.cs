namespace CleanDemo.Domain.Domain;

public class Question
{
    public int QuestionId { get; set; }
    public int QuizId { get; set; }
    public Quiz? Quiz { get; set; }
    public string Text { get; set; } = string.Empty;
    public List<Answer> Answers { get; set; } = new List<Answer>();
}
