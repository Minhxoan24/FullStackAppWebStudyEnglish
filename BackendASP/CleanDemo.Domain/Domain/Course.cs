namespace CleanDemo.Domain.Domain
{
    public class Course
    {

        public int CourseId { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty;
        public CourseStatus Status { get; set; } = CourseStatus.Draft;
        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
        public DateTime? PublishedDate { get; set; }
        public List<Lesson> Lessons { get; set; } = new List<Lesson>();

        public void ValidateCourseName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Course name is required");

            if (name.Length < 10)
                throw new ArgumentException("Course name must be at least 10 characters");

            if (name.Length > 100)
                throw new ArgumentException("Course name cannot exceed 100 characters");

            if (!char.IsLetter(name[0]))
                throw new ArgumentException("Course name must start with a letter");
        }

        public void Publish()
        {
            if (Status != CourseStatus.Draft)
                throw new InvalidOperationException("Only draft courses can be published");

            if (Lessons.Count == 0)
                throw new InvalidOperationException("Course must have at least one lesson to be published");

            Status = CourseStatus.Published;
            PublishedDate = DateTime.UtcNow;
        }

        public void Archive()
        {
            if (Status != CourseStatus.Published)
                throw new InvalidOperationException("Only published courses can be archived");

            Status = CourseStatus.Archived;
        }
    }

    public static class CourseValidation
    {
        public static void ValidateCourseName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Course name is required");

            if (name.Length < 10)
                throw new ArgumentException("Course name must be at least 10 characters");

            if (name.Length > 100)
                throw new ArgumentException("Course name cannot exceed 100 characters");

            if (!char.IsLetter(name[0]))
                throw new ArgumentException("Course name must start with a letter");
        }
    }

    public enum CourseStatus
    {
        Draft = 0,
        Published = 1,
        Archived = 2
    }
}