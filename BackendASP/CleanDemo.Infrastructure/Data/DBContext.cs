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
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<Enrollment> Enrollments { get; set; }
        public DbSet<UserProgress> UserProgresses { get; set; }
        public DbSet<Quiz> Quizzes { get; set; }
        public DbSet<Question> Questions { get; set; }
        public DbSet<Answer> Answers { get; set; }
        public DbSet<UserVocab> UserVocabs { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<Vocab> Vocabs { get; set; }
        public DbSet<Topic> Topics { get; set; }
        public DbSet<ExampleVocabulary> ExampleVocabularies { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Course>()
                .ToTable("Courses")
                .HasMany(c => c.Lessons)
                .WithOne(l => l.Course)
                .HasForeignKey(l => l.CourseId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Lesson>()
                .ToTable("Lessons");

            modelBuilder.Entity<Enrollment>()
                .ToTable("Enrollments")
                .HasOne(e => e.User)
                .WithMany()
                .HasForeignKey(e => e.UserId);

            modelBuilder.Entity<Enrollment>()
                .HasOne(e => e.Course)
                .WithMany()
                .HasForeignKey(e => e.CourseId);

            modelBuilder.Entity<UserProgress>()
                .ToTable("UserProgresses")
                .HasOne(p => p.User)
                .WithMany()
                .HasForeignKey(p => p.UserId);

            modelBuilder.Entity<UserProgress>()
                .HasOne(p => p.Lesson)
                .WithMany()
                .HasForeignKey(p => p.LessonId);

            modelBuilder.Entity<Quiz>()
                .ToTable("Quizzes")
                .HasOne(q => q.Lesson)
                .WithMany()
                .HasForeignKey(q => q.LessonId);

            modelBuilder.Entity<Question>()
                .ToTable("Questions")
                .HasOne(q => q.Quiz)
                .WithMany(qz => qz.Questions)
                .HasForeignKey(q => q.QuizId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Answer>()
                .ToTable("Answers")
                .HasOne(a => a.Question)
                .WithMany(q => q.Answers)
                .HasForeignKey(a => a.QuestionId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<UserVocab>()
                .ToTable("UserVocabs")
                .HasOne(uv => uv.User)
                .WithMany()
                .HasForeignKey(uv => uv.UserId);

            modelBuilder.Entity<UserVocab>()
                .HasOne(uv => uv.Vocab)
                .WithMany()
                .HasForeignKey(uv => uv.VocabId);

            modelBuilder.Entity<User>()
                .ToTable("Users")
                .HasIndex(u => u.Email)
                .IsUnique();

            modelBuilder.Entity<Role>()
                .ToTable("Roles");

            modelBuilder.Entity<Vocab>()
                .ToTable("Vocabs");

            modelBuilder.Entity<AuditLog>()
                .ToTable("AuditLogs");

            modelBuilder.Entity<Topic>()
                .ToTable("Topics");

            modelBuilder.Entity<ExampleVocabulary>()
                .ToTable("ExampleVocabularies");

            // Additional relationships
            modelBuilder.Entity<Vocab>()
                .HasOne(v => v.Topic)
                .WithMany(t => t.Vocabs)
                .HasForeignKey(v => v.TopicId);

            modelBuilder.Entity<ExampleVocabulary>()
                .HasOne(ev => ev.Vocab)
                .WithMany(v => v.ExampleVocabularies)
                .HasForeignKey(ev => ev.VocabId);

            modelBuilder.Entity<User>()
                .HasMany(u => u.Roles)
                .WithMany(r => r.Users)
                .UsingEntity(j => j.ToTable("UserRoles"));

            modelBuilder.Entity<RefreshToken>()
                .ToTable("RefreshTokens")
                .HasOne(rt => rt.User)
                .WithMany()
                .HasForeignKey(rt => rt.UserId);

            // Seed data
            modelBuilder.Entity<Role>().HasData(
                new Role { RoleId = 1, Name = "Admin" },
                new Role { RoleId = 2, Name = "User" }
            );

            modelBuilder.Entity<User>().HasData(
                new User
                {
                    UserId = 1,
                    SureName = "Admin",
                    LastName = "System",
                    Email = "admin@studyenglish.com",
                    PasswordHash = "$2a$11$example.hash.for.admin", // Will be replaced with actual hash
                    PhoneNumber = "1234567890",
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    Status = StatusAccount.Active
                }
            );

            // Seed User-Role relationship for admin
            modelBuilder.Entity<User>()
                .HasMany(u => u.Roles)
                .WithMany(r => r.Users)
                .UsingEntity(j => j
                    .HasData(new { UsersUserId = 1, RolesRoleId = 1 }) // Admin user has Admin role
                );
        }

    }
}