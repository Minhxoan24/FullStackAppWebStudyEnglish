using CleanDemo.Domain.Domain;
namespace CleanDemo.Application.Interface
{
    public interface ILessonRepository
    {
        Task<IEnumerable<Lesson>> GetAllLessonsAsync();
        Task<Lesson?> GetLessonByIdAsync(int id);
        Task AddLessonAsync(Lesson lesson);
        Task UpdateLessonAsync(Lesson lesson);
        Task DeleteLessonAsync(int id);
        Task<IEnumerable<Lesson>> GetLessonsByCourseIdAsync(int courseId);
        Task<int> SaveChangesAsync();
    }
}
