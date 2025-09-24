namespace CleanDemo.Domain.Domain
{
    public class Lesson
    {
        public int LessonId { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;

        public int CourseId { get; set; }
        public Course? Course { get; set; }

    }
}
