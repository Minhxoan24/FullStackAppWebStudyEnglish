namespace CleanDemo.Application.DTOs
{
    public class LessonDto
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public int CourseId { get; set; }
        // public string? CourseName { get; set; }
    }

    public class CreateLessonDto
    {
        public string Title { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public int CourseId { get; set; }
    }

    public class UpdateLessonDto
    {
        public string? Title { get; set; }
        public string? Content { get; set; }
        public int? CourseId { get; set; }
    }
}
