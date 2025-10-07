using Xunit;
using Microsoft.EntityFrameworkCore;
using CleanDemo.Infrastructure.Data;
using CleanDemo.Infrastructure.Repositories;
using CleanDemo.Domain.Domain;

namespace CleanDemo.Tests.Repositories
{
    public class PasswordResetTokenRepositoryTests : IDisposable
    {
        private readonly AppDbContext _context;
        private readonly PasswordResetTokenRepository _repository;

        public PasswordResetTokenRepositoryTests()
        {
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _context = new AppDbContext(options);
            _repository = new PasswordResetTokenRepository(_context);
        }

        [Fact]
        public async Task GetByTokenAsync_WithValidToken_ShouldReturnToken()
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

            var resetToken = new PasswordResetToken
            {
                Token = "valid-token-123",
                UserId = user.UserId,
                User = user,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                IsUsed = false
            };

            _context.Users.Add(user);
            _context.PasswordResetTokens.Add(resetToken);
            await _context.SaveChangesAsync();

            // Act
            var result = await _repository.GetByTokenAsync("valid-token-123");

            // Assert
            Assert.NotNull(result);
            Assert.Equal("valid-token-123", result.Token);
            Assert.False(result.IsUsed);
            Assert.True(result.ExpiresAt > DateTime.UtcNow);
        }

        [Fact]
        public async Task GetByTokenAsync_WithExpiredToken_ShouldReturnNull()
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

            var expiredToken = new PasswordResetToken
            {
                Token = "expired-token-123",
                UserId = user.UserId,
                User = user,
                ExpiresAt = DateTime.UtcNow.AddHours(-1), // Expired
                IsUsed = false
            };

            _context.Users.Add(user);
            _context.PasswordResetTokens.Add(expiredToken);
            await _context.SaveChangesAsync();

            // Act
            var result = await _repository.GetByTokenAsync("expired-token-123");

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task GetByTokenAsync_WithUsedToken_ShouldReturnNull()
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

            var usedToken = new PasswordResetToken
            {
                Token = "used-token-123",
                UserId = user.UserId,
                User = user,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                IsUsed = true // Already used
            };

            _context.Users.Add(user);
            _context.PasswordResetTokens.Add(usedToken);
            await _context.SaveChangesAsync();

            // Act
            var result = await _repository.GetByTokenAsync("used-token-123");

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task AddAsync_ShouldAddTokenToDatabase()
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

            var resetToken = new PasswordResetToken
            {
                Token = "new-token-123",
                UserId = user.UserId,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                IsUsed = false
            };

            // Act
            await _repository.AddAsync(resetToken);
            await _repository.SaveChangesAsync();

            // Assert
            var addedToken = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.Token == "new-token-123");
            Assert.NotNull(addedToken);
            Assert.Equal(user.UserId, addedToken.UserId);
            Assert.False(addedToken.IsUsed);
        }

        [Fact]
        public async Task UpdateAsync_ShouldUpdateToken()
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

            var resetToken = new PasswordResetToken
            {
                Token = "update-token-123",
                UserId = user.UserId,
                User = user,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                IsUsed = false
            };

            _context.Users.Add(user);
            _context.PasswordResetTokens.Add(resetToken);
            await _context.SaveChangesAsync();

            // Act
            resetToken.IsUsed = true;
            await _repository.UpdateAsync(resetToken);
            await _repository.SaveChangesAsync();

            // Assert
            var updatedToken = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.Token == "update-token-123");
            Assert.NotNull(updatedToken);
            Assert.True(updatedToken.IsUsed);
        }

        [Fact]
        public async Task DeleteExpiredTokensAsync_ShouldRemoveExpiredAndUsedTokens()
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

            var validToken = new PasswordResetToken
            {
                Token = "valid-token",
                UserId = user.UserId,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                IsUsed = false
            };

            var expiredToken = new PasswordResetToken
            {
                Token = "expired-token",
                UserId = user.UserId,
                ExpiresAt = DateTime.UtcNow.AddHours(-1),
                IsUsed = false
            };

            var usedToken = new PasswordResetToken
            {
                Token = "used-token",
                UserId = user.UserId,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                IsUsed = true
            };

            _context.Users.Add(user);
            _context.PasswordResetTokens.AddRange(validToken, expiredToken, usedToken);
            await _context.SaveChangesAsync();

            // Act
            await _repository.DeleteExpiredTokensAsync();
            await _repository.SaveChangesAsync();

            // Assert
            var remainingTokens = await _context.PasswordResetTokens.ToListAsync();
            Assert.Single(remainingTokens);
            Assert.Equal("valid-token", remainingTokens[0].Token);
        }

        public void Dispose()
        {
            _context.Dispose();
        }
    }
}
