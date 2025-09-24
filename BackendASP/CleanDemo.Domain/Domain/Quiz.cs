namespace CleanDemo.Domain.Domain;

public class Quiz
{
    public int QuizId { get; set; }
    public int LessonId { get; set; }
    public Lesson? Lesson { get; set; }
    public string Title { get; set; } = string.Empty;
    public List<Question> Questions { get; set; } = new List<Question>();
}
