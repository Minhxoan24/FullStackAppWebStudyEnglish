using Xunit;
using Microsoft.EntityFrameworkCore;
using CleanDemo.Infrastructure.Data;
using CleanDemo.Infrastructure.Repositories;
using CleanDemo.Domain.Domain;

namespace CleanDemo.Tests.Repositories
{
    public class UserRepositoryTests : IDisposable
    {
        private readonly AppDbContext _context;
        private readonly UserRepository _userRepository;

        public UserRepositoryTests()
        {
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new AppDbContext(options);
            _userRepository = new UserRepository(_context);
        }

        [Fact]
        public async Task GetUserByEmailAsync_WithExistingEmail_ShouldReturnUser()
        {
            // Arrange
            var user = new User
            {
                Email = "test@example.com",
                SureName = "John",
                LastName = "Doe",
                PhoneNumber = "1234567890"
            };
            user.SetPassword("Test123!");

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Act
            var result = await _userRepository.GetUserByEmailAsync("test@example.com");

            // Assert
            Assert.NotNull(result);
            Assert.Equal("test@example.com", result.Email);
            Assert.Equal("John", result.SureName);
        }

        [Fact]
        public async Task GetUserByEmailAsync_WithNonExistingEmail_ShouldReturnNull()
        {
            // Act
            var result = await _userRepository.GetUserByEmailAsync("nonexistent@example.com");

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task GetUserByIdAsync_WithExistingId_ShouldReturnUser()
        {
            // Arrange
            var user = new User
            {
                Email = "test@example.com",
                SureName = "John",
                LastName = "Doe",
                PhoneNumber = "1234567890"
            };
            user.SetPassword("Test123!");

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Act
            var result = await _userRepository.GetUserByIdAsync(user.UserId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(user.UserId, result.UserId);
            Assert.Equal("test@example.com", result.Email);
        }

        [Fact]
        public async Task AddUserAsync_ShouldAddUserToDatabase()
        {
            // Arrange
            var user = new User
            {
                Email = "newuser@example.com",
                SureName = "Jane",
                LastName = "Smith",
                PhoneNumber = "0987654321"
            };
            user.SetPassword("NewPass123!");

            // Act
            await _userRepository.AddUserAsync(user);
            await _userRepository.SaveChangesAsync();

            // Assert
            var addedUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == "newuser@example.com");
            Assert.NotNull(addedUser);
            Assert.Equal("Jane", addedUser.SureName);
            Assert.Equal("Smith", addedUser.LastName);
        }

        [Fact]
        public async Task UpdateUserAsync_ShouldUpdateUserInDatabase()
        {
            // Arrange
            var user = new User
            {
                Email = "update@example.com",
                SureName = "Original",
                LastName = "Name",
                PhoneNumber = "1111111111"
            };
            user.SetPassword("Original123!");

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Act
            user.SureName = "Updated";
            user.LastName = "UpdatedName";
            await _userRepository.UpdateUserAsync(user);
            await _userRepository.SaveChangesAsync();

            // Assert
            var updatedUser = await _context.Users.FirstOrDefaultAsync(u => u.UserId == user.UserId);
            Assert.NotNull(updatedUser);
            Assert.Equal("Updated", updatedUser.SureName);
            Assert.Equal("UpdatedName", updatedUser.LastName);
        }

        [Fact]
        public async Task GetAllUsersAsync_ShouldReturnAllUsers()
        {
            // Arrange
            var users = new List<User>
            {
                new User { Email = "user1@example.com", SureName = "User", LastName = "One", PhoneNumber = "1111111111" },
                new User { Email = "user2@example.com", SureName = "User", LastName = "Two", PhoneNumber = "2222222222" },
                new User { Email = "user3@example.com", SureName = "User", LastName = "Three", PhoneNumber = "3333333333" }
            };

            foreach (var user in users)
            {
                user.SetPassword("Test123!");
            }

            _context.Users.AddRange(users);
            await _context.SaveChangesAsync();

            // Act
            var result = await _userRepository.GetAllUsersAsync();

            // Assert
            Assert.NotNull(result);
            Assert.Equal(3, result.Count);
            Assert.Contains(result, u => u.Email == "user1@example.com");
            Assert.Contains(result, u => u.Email == "user2@example.com");
            Assert.Contains(result, u => u.Email == "user3@example.com");
        }

        [Fact]
        public async Task DeleteUserAsync_ShouldRemoveUserFromDatabase()
        {
            // Arrange
            var user = new User
            {
                Email = "delete@example.com",
                SureName = "Delete",
                LastName = "Me",
                PhoneNumber = "9999999999"
            };
            user.SetPassword("Delete123!");

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            var userId = user.UserId;

            // Act
            await _userRepository.DeleteUserAsync(userId);
            await _userRepository.SaveChangesAsync();

            // Assert
            var deletedUser = await _context.Users.FirstOrDefaultAsync(u => u.UserId == userId);
            Assert.Null(deletedUser);
        }

        public void Dispose()
        {
            _context.Dispose();
        }
    }
}
