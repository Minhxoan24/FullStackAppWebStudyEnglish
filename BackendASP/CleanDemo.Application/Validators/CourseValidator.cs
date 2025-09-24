using CleanDemo.Application.DTOs;
using CleanDemo.Domain.Domain;

namespace CleanDemo.Application.Validators
{
    public class CourseValidator : ICourseValidator
    {
        public void ValidateCreateCourse(CreateCourseDto dto)
        {
            if (dto == null)
                throw new ArgumentNullException(nameof(dto));

            CourseValidation.ValidateCourseName(dto.Name);

            if (string.IsNullOrWhiteSpace(dto.Description))
                throw new ArgumentException("Course description is required");
            
            if (string.IsNullOrWhiteSpace(dto.Level))
                throw new ArgumentException("Course level is required");
        }

        public void ValidateUpdateCourse(UpdateCourseDto dto)
        {
            if (dto == null)
                throw new ArgumentNullException(nameof(dto));

            if (!string.IsNullOrWhiteSpace(dto.Name))
            {
                CourseValidation.ValidateCourseName(dto.Name);
            }

            if (!string.IsNullOrWhiteSpace(dto.Description))
            {
                if (dto.Description.Length < 20)
                    throw new ArgumentException("Course description must be at least 20 characters");
            }
        }
    }
}
