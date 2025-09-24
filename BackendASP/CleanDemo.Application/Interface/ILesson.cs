using CleanDemo.Application.DTOs;
using CleanDemo.Application.Common;

namespace CleanDemo.Application.Interface
{
    public interface ILessonService
    {
        Task<ServiceResponse<List<LessonDto>>> GetAllLessonsAsync();
        Task<ServiceResponse<LessonDto>> GetLessonByIdAsync(int id);
        Task<ServiceResponse<LessonDto>> CreateLessonAsync(CreateLessonDto createLessonDto);
        Task<ServiceResponse<LessonDto>> UpdateLessonAsync(int id, UpdateLessonDto updateLessonDto);
        Task<ServiceResponse<bool>> DeleteLessonAsync(int id);
        Task<ServiceResponse<List<LessonDto>>> GetLessonsByCourseIdAsync(int courseId);
    }
}

// using CleanDemo.Application.DTOs;


// namespace CleanDemo.Application.Interface
// {
//     public interface ILessonService
//     {
//         Task<List<LessonDto>> GetAllLessonsAsync();
//         Task<LessonDto?> GetLessonByIdAsync(int id);
//         Task<LessonDto> CreateLessonAsync(CreateLessonDto createLessonDto);
//         Task<LessonDto?> UpdateLessonAsync(int id, UpdateLessonDto updateLessonDto);
//         Task<bool> DeleteLessonAsync(int id);
//         Task<List<LessonDto>> GetLessonsByCourseIdAsync(int courseId);
//     }

// }