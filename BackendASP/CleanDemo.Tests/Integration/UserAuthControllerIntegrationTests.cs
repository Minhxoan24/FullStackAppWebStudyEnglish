using Xunit;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using System.Net.Http.Json;
using System.Net;
using CleanDemo.API;
using CleanDemo.Infrastructure.Data;
using CleanDemo.Application.DTOs;
using CleanDemo.Domain.Domain;

namespace CleanDemo.Tests.Integration
{
    public class UserAuthControllerIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly WebApplicationFactory<Program> _factory;
        private readonly HttpClient _client;

        public UserAuthControllerIntegrationTests(WebApplicationFactory<Program> factory)
        {
            _factory = factory.WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    // Remove the real database
                    var descriptor = services.SingleOrDefault(
                        d => d.ServiceType == typeof(DbContextOptions<AppDbContext>));
                    if (descriptor != null)
                        services.Remove(descriptor);

                    // Add in-memory database for testing
                    services.AddDbContext<AppDbContext>(options =>
                    {
                        options.UseInMemoryDatabase("TestDatabase");
                    });
                });
            });

            _client = _factory.CreateClient();
        }

        [Fact]
        public async Task Register_WithValidData_ShouldReturnCreated()
        {
            // Arrange
            var registerDto = new RegisterUserDto
            {
                Email = "integration@test.com",
                Password = "IntegrationTest123!",
                SureName = "Integration",
                LastName = "Test",
                PhoneNumber = "1234567890"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/user/auth/register", registerDto);

            // Assert
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        }

        [Fact]
        public async Task Register_WithExistingEmail_ShouldReturnBadRequest()
        {
            // Arrange
            var registerDto = new RegisterUserDto
            {
                Email = "duplicate@test.com",
                Password = "Test123!",
                SureName = "Test",
                LastName = "User",
                PhoneNumber = "1234567890"
            };

            // First registration
            await _client.PostAsJsonAsync("/api/user/auth/register", registerDto);

            // Act - Second registration with same email
            var response = await _client.PostAsJsonAsync("/api/user/auth/register", registerDto);

            // Assert
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task Login_WithValidCredentials_ShouldReturnOk()
        {
            // Arrange
            var registerDto = new RegisterUserDto
            {
                Email = "login@test.com",
                Password = "LoginTest123!",
                SureName = "Login",
                LastName = "Test",
                PhoneNumber = "1234567890"
            };

            var loginDto = new LoginUserDto
            {
                Email = "login@test.com",
                Password = "LoginTest123!"
            };

            // Register user first
            await _client.PostAsJsonAsync("/api/user/auth/register", registerDto);

            // Act
            var response = await _client.PostAsJsonAsync("/api/user/auth/login", loginDto);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            
            var content = await response.Content.ReadAsStringAsync();
            Assert.Contains("accessToken", content);
            Assert.Contains("refreshToken", content);
        }

        [Fact]
        public async Task Login_WithInvalidCredentials_ShouldReturnUnauthorized()
        {
            // Arrange
            var loginDto = new LoginUserDto
            {
                Email = "nonexistent@test.com",
                Password = "WrongPassword123!"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/user/auth/login", loginDto);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ForgotPassword_WithValidEmail_ShouldReturnOk()
        {
            // Arrange
            var registerDto = new RegisterUserDto
            {
                Email = "forgot@test.com",
                Password = "ForgotTest123!",
                SureName = "Forgot",
                LastName = "Test",
                PhoneNumber = "1234567890"
            };

            var forgotDto = new ForgotPasswordDto
            {
                Email = "forgot@test.com"
            };

            // Register user first
            await _client.PostAsJsonAsync("/api/user/auth/register", registerDto);

            // Act
            var response = await _client.PostAsJsonAsync("/api/user/auth/forgot-password", forgotDto);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task ForgotPassword_WithInvalidEmail_ShouldReturnOk()
        {
            // Arrange
            var forgotDto = new ForgotPasswordDto
            {
                Email = "nonexistent@test.com"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/user/auth/forgot-password", forgotDto);

            // Assert
            // Should return OK for security reasons (don't reveal if email exists)
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task GetProfile_WithoutAuthentication_ShouldReturnUnauthorized()
        {
            // Act
            var response = await _client.GetAsync("/api/user/auth/profile");

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task GetProfile_WithValidAuthentication_ShouldReturnOk()
        {
            // Arrange
            var registerDto = new RegisterUserDto
            {
                Email = "profile@test.com",
                Password = "ProfileTest123!",
                SureName = "Profile",
                LastName = "Test",
                PhoneNumber = "1234567890"
            };

            var loginDto = new LoginUserDto
            {
                Email = "profile@test.com",
                Password = "ProfileTest123!"
            };

            // Register and login
            await _client.PostAsJsonAsync("/api/user/auth/register", registerDto);
            var loginResponse = await _client.PostAsJsonAsync("/api/user/auth/login", loginDto);
            var loginContent = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();

            // Set authorization header
            _client.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", loginContent?.AccessToken);

            // Act
            var response = await _client.GetAsync("/api/user/auth/profile");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            
            var profileContent = await response.Content.ReadAsStringAsync();
            Assert.Contains("profile@test.com", profileContent);
        }

        [Fact]
        public async Task ChangePassword_WithValidData_ShouldReturnOk()
        {
            // Arrange
            var registerDto = new RegisterUserDto
            {
                Email = "changepass@test.com",
                Password = "OldPassword123!",
                SureName = "Change",
                LastName = "Password",
                PhoneNumber = "1234567890"
            };

            var loginDto = new LoginUserDto
            {
                Email = "changepass@test.com",
                Password = "OldPassword123!"
            };

            var changePasswordDto = new ChangePasswordDto
            {
                CurrentPassword = "OldPassword123!",
                NewPassword = "NewPassword123!"
            };

            // Register and login
            await _client.PostAsJsonAsync("/api/user/auth/register", registerDto);
            var loginResponse = await _client.PostAsJsonAsync("/api/user/auth/login", loginDto);
            var loginContent = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();

            // Set authorization header
            _client.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", loginContent?.AccessToken);

            // Act
            var response = await _client.PutAsJsonAsync("/api/user/auth/change-password", changePasswordDto);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task ChangePassword_WithWrongCurrentPassword_ShouldReturnBadRequest()
        {
            // Arrange
            var registerDto = new RegisterUserDto
            {
                Email = "wrongpass@test.com",
                Password = "CorrectPassword123!",
                SureName = "Wrong",
                LastName = "Password",
                PhoneNumber = "1234567890"
            };

            var loginDto = new LoginUserDto
            {
                Email = "wrongpass@test.com",
                Password = "CorrectPassword123!"
            };

            var changePasswordDto = new ChangePasswordDto
            {
                CurrentPassword = "WrongPassword123!", // Wrong current password
                NewPassword = "NewPassword123!"
            };

            // Register and login
            await _client.PostAsJsonAsync("/api/user/auth/register", registerDto);
            var loginResponse = await _client.PostAsJsonAsync("/api/user/auth/login", loginDto);
            var loginContent = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>();

            // Set authorization header
            _client.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", loginContent?.AccessToken);

            // Act
            var response = await _client.PutAsJsonAsync("/api/user/auth/change-password", changePasswordDto);

            // Assert
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }
}
