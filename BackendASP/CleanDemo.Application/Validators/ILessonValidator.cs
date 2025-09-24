using CleanDemo.Application.DTOs;

namespace CleanDemo.Application.Validators
{
    public interface ILessonValidator
    {
        void ValidateCreateLesson(CreateLessonDto dto);
        void ValidateUpdateLesson(UpdateLessonDto dto);
    }
}
