using CleanDemo.Application.DTOs;

namespace CleanDemo.Application.Validators
{
    public class LessonValidator : ILessonValidator
    {
        public void ValidateCreateLesson(CreateLessonDto dto)
        {
            if (dto == null)
                throw new ArgumentNullException(nameof(dto));
            if (string.IsNullOrWhiteSpace(dto.Title))
                throw new ArgumentException("Lesson title is required");
            if (string.IsNullOrWhiteSpace(dto.Content))
                throw new ArgumentException("Lesson content is required");
            if (dto.CourseId <= 0)
                throw new ArgumentException("Valid Course ID is required");
        }

        public void ValidateUpdateLesson(UpdateLessonDto dto)
        {
            if (dto == null)
                throw new ArgumentNullException(nameof(dto));
            if (string.IsNullOrWhiteSpace(dto.Title))
                throw new ArgumentException("Lesson title is required");
            if (string.IsNullOrWhiteSpace(dto.Content))
                throw new ArgumentException("Lesson content is required");
        }
    }
}
