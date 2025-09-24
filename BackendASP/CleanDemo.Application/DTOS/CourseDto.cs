using CleanDemo.Domain.Domain;

namespace CleanDemo.Application.DTOs
{
    public class CourseDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty;
        public CourseStatus Status { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime? PublishedDate { get; set; }
        public List<LessonDto>? Lessons { get; set; }
    }

    public class CreateCourseDto
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty;
    }

    public class UpdateCourseDto
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? Level { get; set; }
    }
}