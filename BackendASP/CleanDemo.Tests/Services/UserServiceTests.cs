using Xunit;
using Moq;
using AutoMapper;
using Microsoft.Extensions.Configuration;
using CleanDemo.Application.Service;
using CleanDemo.Application.Interface;
using CleanDemo.Application.DTOs;
using CleanDemo.Domain.Domain;
using CleanDemo.Application.Common;

namespace CleanDemo.Tests.Services
{
    public class UserServiceTests
    {
        private readonly Mock<IUserRepository> _mockUserRepository;
        private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;
        private readonly Mock<IPasswordResetTokenRepository> _mockPasswordResetTokenRepository;
        private readonly Mock<IMapper> _mockMapper;
        private readonly Mock<IConfiguration> _mockConfiguration;
        private readonly Mock<EmailService> _mockEmailService;
        private readonly UserService _userService;

        public UserServiceTests()
        {
            _mockUserRepository = new Mock<IUserRepository>();
            _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
            _mockPasswordResetTokenRepository = new Mock<IPasswordResetTokenRepository>();
            _mockMapper = new Mock<IMapper>();
            _mockConfiguration = new Mock<IConfiguration>();
            _mockEmailService = new Mock<EmailService>(_mockConfiguration.Object);

            _userService = new UserService(
                _mockUserRepository.Object,
                _mockRefreshTokenRepository.Object,
                _mockPasswordResetTokenRepository.Object,
                _mockMapper.Object,
                _mockConfiguration.Object,
                _mockEmailService.Object
            );
        }

        [Fact]
        public async Task RegisterUserAsync_WithNewEmail_ShouldReturnSuccess()
        {
            // Arrange
            var registerDto = new RegisterUserDto
            {
                Email = "test@example.com",
                Password = "Test123!",
                SureName = "John",
                LastName = "Doe",
                PhoneNumber = "1234567890"
            };

            var user = new User
            {
                Email = registerDto.Email,
                SureName = registerDto.SureName,
                LastName = registerDto.LastName,
                PhoneNumber = registerDto.PhoneNumber
            };

            var userDto = new UserDto
            {
                UserId = 1,
                Name = "John Doe",
                Email = registerDto.Email,
                PhoneNumber = registerDto.PhoneNumber
            };

            _mockUserRepository.Setup(x => x.GetUserByEmailAsync(registerDto.Email))
                .ReturnsAsync((User?)null);
            _mockMapper.Setup(x => x.Map<User>(registerDto)).Returns(user);
            _mockMapper.Setup(x => x.Map<UserDto>(user)).Returns(userDto);
            _mockUserRepository.Setup(x => x.AddUserAsync(It.IsAny<User>())).Returns(Task.CompletedTask);
            _mockUserRepository.Setup(x => x.SaveChangesAsync()).Returns(Task.CompletedTask);

            // Act
            var result = await _userService.RegisterUserAsync(registerDto);

            // Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.Equal(registerDto.Email, result.Data.Email);
            _mockUserRepository.Verify(x => x.AddUserAsync(It.IsAny<User>()), Times.Once);
            _mockUserRepository.Verify(x => x.SaveChangesAsync(), Times.Once);
        }

        [Fact]
        public async Task RegisterUserAsync_WithExistingEmail_ShouldReturnFailure()
        {
            // Arrange
            var registerDto = new RegisterUserDto
            {
                Email = "existing@example.com",
                Password = "Test123!",
                SureName = "John",
                LastName = "Doe",
                PhoneNumber = "1234567890"
            };

            var existingUser = new User { Email = registerDto.Email };

            _mockUserRepository.Setup(x => x.GetUserByEmailAsync(registerDto.Email))
                .ReturnsAsync(existingUser);

            // Act
            var result = await _userService.RegisterUserAsync(registerDto);

            // Assert
            Assert.False(result.Success);
            Assert.Equal("Email already exists", result.Message);
            _mockUserRepository.Verify(x => x.AddUserAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task ChangePasswordAsync_WithCorrectCurrentPassword_ShouldReturnSuccess()
        {
            // Arrange
            var userId = 1;
            var dto = new ChangePasswordDto
            {
                CurrentPassword = "OldPass123!",
                NewPassword = "NewPass123!"
            };

            var user = new User
            {
                UserId = userId,
                Email = "test@example.com"
            };
            user.SetPassword("OldPass123!");

            _mockUserRepository.Setup(x => x.GetUserByIdAsync(userId)).ReturnsAsync(user);
            _mockRefreshTokenRepository.Setup(x => x.GetTokensByUserIdAsync(userId))
                .ReturnsAsync(new List<RefreshToken>());
            _mockUserRepository.Setup(x => x.UpdateUserAsync(It.IsAny<User>())).Returns(Task.CompletedTask);
            _mockUserRepository.Setup(x => x.SaveChangesAsync()).Returns(Task.CompletedTask);
            _mockRefreshTokenRepository.Setup(x => x.SaveChangesAsync()).Returns(Task.CompletedTask);

            // Act
            var result = await _userService.ChangePasswordAsync(userId, dto);

            // Assert
            Assert.True(result.Success);
            Assert.True(result.Data);
            Assert.Contains("Password changed successfully", result.Message);
            _mockUserRepository.Verify(x => x.UpdateUserAsync(It.IsAny<User>()), Times.Once);
        }

        [Fact]
        public async Task ChangePasswordAsync_WithIncorrectCurrentPassword_ShouldReturnFailure()
        {
            // Arrange
            var userId = 1;
            var dto = new ChangePasswordDto
            {
                CurrentPassword = "WrongPassword",
                NewPassword = "NewPass123!"
            };

            var user = new User
            {
                UserId = userId,
                Email = "test@example.com"
            };
            user.SetPassword("CorrectPassword123!");

            _mockUserRepository.Setup(x => x.GetUserByIdAsync(userId)).ReturnsAsync(user);

            // Act
            var result = await _userService.ChangePasswordAsync(userId, dto);

            // Assert
            Assert.False(result.Success);
            Assert.Equal("Invalid current password", result.Message);
            _mockUserRepository.Verify(x => x.UpdateUserAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task ChangePasswordAsync_WithWeakNewPassword_ShouldReturnFailure()
        {
            // Arrange
            var userId = 1;
            var dto = new ChangePasswordDto
            {
                CurrentPassword = "OldPass123!",
                NewPassword = "weak" // Weak password
            };

            var user = new User
            {
                UserId = userId,
                Email = "test@example.com"
            };
            user.SetPassword("OldPass123!");

            _mockUserRepository.Setup(x => x.GetUserByIdAsync(userId)).ReturnsAsync(user);

            // Act
            var result = await _userService.ChangePasswordAsync(userId, dto);

            // Assert
            Assert.False(result.Success);
            Assert.Contains("Password must contain at least 8 characters", result.Message);
            _mockUserRepository.Verify(x => x.UpdateUserAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task ForgotPasswordAsync_WithValidEmail_ShouldSendEmail()
        {
            // Arrange
            var email = "test@example.com";
            var user = new User
            {
                UserId = 1,
                Email = email
            };

            var configSection = new Mock<IConfigurationSection>();
            configSection.Setup(x => x["BaseUrl"]).Returns("http://localhost:3000");
            _mockConfiguration.Setup(x => x.GetSection("Frontend")).Returns(configSection.Object);

            _mockUserRepository.Setup(x => x.GetUserByEmailAsync(email)).ReturnsAsync(user);
            _mockPasswordResetTokenRepository.Setup(x => x.AddAsync(It.IsAny<PasswordResetToken>()))
                .Returns(Task.CompletedTask);
            _mockPasswordResetTokenRepository.Setup(x => x.SaveChangesAsync()).Returns(Task.CompletedTask);
            _mockEmailService.Setup(x => x.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            // Act
            var result = await _userService.ForgotPasswordAsync(email);

            // Assert
            Assert.True(result.Success);
            Assert.Contains("password reset link has been sent", result.Message);
            _mockPasswordResetTokenRepository.Verify(x => x.AddAsync(It.IsAny<PasswordResetToken>()), Times.Once);
            _mockEmailService.Verify(x => x.SendEmailAsync(email, It.IsAny<string>(), It.IsAny<string>()), Times.Once);
        }

        [Fact]
        public async Task ForgotPasswordAsync_WithInvalidEmail_ShouldReturnSuccessButNotSendEmail()
        {
            // Arrange
            var email = "nonexistent@example.com";

            _mockUserRepository.Setup(x => x.GetUserByEmailAsync(email))
                .ReturnsAsync((User?)null);

            // Act
            var result = await _userService.ForgotPasswordAsync(email);

            // Assert
            Assert.True(result.Success); // Should return success for security
            Assert.Contains("password reset link has been sent", result.Message);
            _mockPasswordResetTokenRepository.Verify(x => x.AddAsync(It.IsAny<PasswordResetToken>()), Times.Never);
            _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task ResetPasswordAsync_WithValidToken_ShouldResetPassword()
        {
            // Arrange
            var dto = new ResetPasswordDto
            {
                Token = "valid-token",
                NewPassword = "NewSecure123!"
            };

            var user = new User
            {
                UserId = 1,
                Email = "test@example.com"
            };

            var resetToken = new PasswordResetToken
            {
                Token = dto.Token,
                UserId = user.UserId,
                User = user,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                IsUsed = false
            };

            _mockPasswordResetTokenRepository.Setup(x => x.GetByTokenAsync(dto.Token))
                .ReturnsAsync(resetToken);
            _mockUserRepository.Setup(x => x.UpdateUserAsync(It.IsAny<User>())).Returns(Task.CompletedTask);
            _mockPasswordResetTokenRepository.Setup(x => x.UpdateAsync(It.IsAny<PasswordResetToken>()))
                .Returns(Task.CompletedTask);
            _mockUserRepository.Setup(x => x.SaveChangesAsync()).Returns(Task.CompletedTask);
            _mockPasswordResetTokenRepository.Setup(x => x.SaveChangesAsync()).Returns(Task.CompletedTask);

            // Act
            var result = await _userService.ResetPasswordAsync(dto);

            // Assert
            Assert.True(result.Success);
            Assert.True(result.Data);
            Assert.Contains("Password has been reset successfully", result.Message);
            Assert.True(resetToken.IsUsed);
            _mockUserRepository.Verify(x => x.UpdateUserAsync(It.IsAny<User>()), Times.Once);
            _mockPasswordResetTokenRepository.Verify(x => x.UpdateAsync(resetToken), Times.Once);
        }

        [Fact]
        public async Task ResetPasswordAsync_WithInvalidToken_ShouldReturnFailure()
        {
            // Arrange
            var dto = new ResetPasswordDto
            {
                Token = "invalid-token",
                NewPassword = "NewSecure123!"
            };

            _mockPasswordResetTokenRepository.Setup(x => x.GetByTokenAsync(dto.Token))
                .ReturnsAsync((PasswordResetToken?)null);

            // Act
            var result = await _userService.ResetPasswordAsync(dto);

            // Assert
            Assert.False(result.Success);
            Assert.Equal("Invalid or expired reset token", result.Message);
            _mockUserRepository.Verify(x => x.UpdateUserAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task GetUserProfileAsync_WithValidUserId_ShouldReturnUser()
        {
            // Arrange
            var userId = 1;
            var user = new User
            {
                UserId = userId,
                Email = "test@example.com",
                SureName = "John",
                LastName = "Doe"
            };

            var userDto = new UserDto
            {
                UserId = userId,
                Email = user.Email,
                Name = "John Doe"
            };

            _mockUserRepository.Setup(x => x.GetUserByIdAsync(userId)).ReturnsAsync(user);
            _mockMapper.Setup(x => x.Map<UserDto>(user)).Returns(userDto);

            // Act
            var result = await _userService.GetUserProfileAsync(userId);

            // Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.Equal(userDto.Email, result.Data.Email);
            Assert.Equal(userDto.Name, result.Data.Name);
        }

        [Fact]
        public async Task GetUserProfileAsync_WithInvalidUserId_ShouldReturnFailure()
        {
            // Arrange
            var userId = 999;

            _mockUserRepository.Setup(x => x.GetUserByIdAsync(userId))
                .ReturnsAsync((User?)null);

            // Act
            var result = await _userService.GetUserProfileAsync(userId);

            // Assert
            Assert.False(result.Success);
            Assert.Equal("User not found", result.Message);
            Assert.Null(result.Data);
        }
    }
}
