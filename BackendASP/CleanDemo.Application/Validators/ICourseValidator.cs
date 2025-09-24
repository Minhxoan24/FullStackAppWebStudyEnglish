using CleanDemo.Application.DTOs;

namespace CleanDemo.Application.Validators
{
    public interface ICourseValidator
    {
        void ValidateCreateCourse(CreateCourseDto dto);
        void ValidateUpdateCourse(UpdateCourseDto dto);
    }
}
