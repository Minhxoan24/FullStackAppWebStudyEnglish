namespace CleanDemo.Domain.Domain;

public class Enrollment
{
    public int EnrollmentId { get; set; }
    public int UserId { get; set; }
    public User? User { get; set; }
    public int CourseId { get; set; }
    public Course? Course { get; set; }
    public DateTime EnrolledDate { get; set; } = DateTime.UtcNow;
    public EnrollmentStatus Status { get; set; } = EnrollmentStatus.Active;
}

public enum EnrollmentStatus
{
    Active,
    Completed,
    Dropped
}
