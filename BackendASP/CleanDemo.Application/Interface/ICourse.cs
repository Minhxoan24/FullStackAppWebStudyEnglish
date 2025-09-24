using CleanDemo.Application.DTOs;
using CleanDemo.Application.Common;

namespace CleanDemo.Application.Interface
{
    public interface ICourseService
    {
        Task<ServiceResponse<IEnumerable<CourseDto>>> GetAllCoursesAsync();
        Task<ServiceResponse<CourseDto>> GetCourseByIdAsync(int id);
        Task<ServiceResponse<CourseDto>> CreateCourseAsync(CreateCourseDto createCourseDto);
        Task<ServiceResponse<CourseDto>> UpdateCourseAsync(int id, UpdateCourseDto updateCourseDto);
        Task<ServiceResponse<bool>> DeleteCourseAsync(int id);
        Task<ServiceResponse<CourseDto>> PublishCourseAsync(int courseId);
        Task<ServiceResponse<CourseDto>> ArchiveCourseAsync(int courseId);
    }
}