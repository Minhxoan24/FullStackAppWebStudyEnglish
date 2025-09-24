using CleanDemo.Application.Interface;
using CleanDemo.Domain.Domain;
using CleanDemo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
namespace CleanDemo.Infrastructure.Repositories
{
    public class LessonRepository : ILessonRepository
    {
        private readonly AppDbContext _context;
        public LessonRepository(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IEnumerable<Lesson>> GetAllLessonsAsync()
        {
            return await _context.Lessons.ToListAsync();
        }

        public async Task<Lesson?> GetLessonByIdAsync(int id)
        {
            return await _context.Lessons.FindAsync(id);
        }

        public async Task AddLessonAsync(Lesson lesson)
        {
            await _context.Lessons.AddAsync(lesson);
        }

        public Task UpdateLessonAsync(Lesson lesson)
        {
            _context.Lessons.Update(lesson);
            return Task.CompletedTask;
        }

        public async Task DeleteLessonAsync(int id)
        {
            var lesson = await _context.Lessons.FindAsync(id);
            if (lesson != null)
            {
                _context.Lessons.Remove(lesson);
            }
        }

        public async Task<IEnumerable<Lesson>> GetLessonsByCourseIdAsync(int courseId)
        {
            return await _context.Lessons
                                 .Where(l => l.CourseId == courseId)
                                 .ToListAsync();
        }

        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }
    }
}