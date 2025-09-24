namespace CleanDemo.Domain.Domain;

public class UserProgress
{
    public int UserProgressId { get; set; }
    public int UserId { get; set; }
    public User? User { get; set; }
    public int LessonId { get; set; }
    public Lesson? Lesson { get; set; }
    public bool IsCompleted { get; set; } = false;
    public int Score { get; set; }
    public DateTime? CompletedDate { get; set; }
}
