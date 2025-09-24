using Microsoft.EntityFrameworkCore;
using CleanDemo.Domain.Domain;
namespace CleanDemo.Infrastructure.Data

{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
        public DbSet<Course> Courses { get; set; }
        public DbSet<Lesson> Lessons { get; set; }
        public DbSet<Enrollment> Enrollments { get; set; }
        public DbSet<UserProgress> UserProgresses { get; set; }
        public DbSet<Quiz> Quizzes { get; set; }
        public DbSet<Question> Questions { get; set; }
        public DbSet<Answer> Answers { get; set; }
        public DbSet<UserVocab> UserVocabs { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Course>()
                .HasMany(c => c.Lessons)
                .WithOne(l => l.Course)
                .HasForeignKey(l => l.CourseId)
                .OnDelete(DeleteBehavior.Cascade);

            // Enrollment: Many-to-one with User and Course
            modelBuilder.Entity<Enrollment>()
                .HasOne(e => e.User)
                .WithMany()  // User can have many enrollments
                .HasForeignKey(e => e.UserId);

            modelBuilder.Entity<Enrollment>()
                .HasOne(e => e.Course)
                .WithMany()  // Course can have many enrollments
                .HasForeignKey(e => e.CourseId);

            // UserProgress: Many-to-one with User and Lesson
            modelBuilder.Entity<UserProgress>()
                .HasOne(p => p.User)
                .WithMany()
                .HasForeignKey(p => p.UserId);

            modelBuilder.Entity<UserProgress>()
                .HasOne(p => p.Lesson)
                .WithMany()
                .HasForeignKey(p => p.LessonId);

            // Quiz: One-to-many with Lesson
            modelBuilder.Entity<Quiz>()
                .HasOne(q => q.Lesson)
                .WithMany()
                .HasForeignKey(q => q.LessonId);

            // Question: One-to-many with Quiz
            modelBuilder.Entity<Question>()
                .HasOne(q => q.Quiz)
                .WithMany(qz => qz.Questions)
                .HasForeignKey(q => q.QuizId)
                .OnDelete(DeleteBehavior.Cascade);

            // Answer: One-to-many with Question
            modelBuilder.Entity<Answer>()
                .HasOne(a => a.Question)
                .WithMany(q => q.Answers)
                .HasForeignKey(a => a.QuestionId)
                .OnDelete(DeleteBehavior.Cascade);

            // UserVocab: Many-to-one with User and Vocab
            modelBuilder.Entity<UserVocab>()
                .HasOne(uv => uv.User)
                .WithMany()
                .HasForeignKey(uv => uv.UserId);

            modelBuilder.Entity<UserVocab>()
                .HasOne(uv => uv.Vocab)
                .WithMany()
                .HasForeignKey(uv => uv.VocabId);
        }

    }
}