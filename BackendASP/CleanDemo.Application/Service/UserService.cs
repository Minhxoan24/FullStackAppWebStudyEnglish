using CleanDemo.Application.DTOs;
using CleanDemo.Application.Interface;
using CleanDemo.Application.Common;
using CleanDemo.Domain.Domain;
using AutoMapper;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace CleanDemo.Application.Service
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly IMapper _mapper;
        private readonly IConfiguration _configuration;
        private readonly EmailService _emailService;

        public UserService(IUserRepository userRepository, IRefreshTokenRepository refreshTokenRepository, IMapper mapper, IConfiguration configuration, EmailService emailService)
        {
            _userRepository = userRepository;
            _refreshTokenRepository = refreshTokenRepository;
            _mapper = mapper;
            _configuration = configuration;
            _emailService = emailService;
        }

        public async Task<ServiceResponse<UserDto>> RegisterUserAsync(RegisterUserDto dto)
        {
            var response = new ServiceResponse<UserDto>();
            try
            {
                var existingUser = await _userRepository.GetUserByEmailAsync(dto.Email);
                if (existingUser != null)
                {
                    response.Success = false;
                    response.Message = "Email already exists";
                    return response;
                }

                var user = _mapper.Map<User>(dto);
                user.SetPassword(dto.Password);
                // Assign default role
                user.Roles = new List<Role> { new Role { Name = "User" } };

                await _userRepository.AddUserAsync(user);
                await _userRepository.SaveChangesAsync();

                response.Data = _mapper.Map<UserDto>(user);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<AuthResponseDto>> LoginUserAsync(LoginUserDto dto)
        {
            var response = new ServiceResponse<AuthResponseDto>();
            try
            {
                var user = await _userRepository.GetUserByEmailAsync(dto.Email);
                if (user == null || !user.VerifyPassword(dto.Password))
                {
                    response.Success = false;
                    response.Message = "Invalid email or password";
                    return response;
                }

                var accessToken = GenerateJwtToken(user);
                var refreshToken = GenerateRefreshToken(user);

                await _refreshTokenRepository.AddAsync(refreshToken);
                await _refreshTokenRepository.SaveChangesAsync();

                response.Data = new AuthResponseDto { AccessToken = accessToken, RefreshToken = refreshToken.Token, User = _mapper.Map<UserDto>(user) };
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<UserDto>> GetUserProfileAsync(int userId)
        {
            var response = new ServiceResponse<UserDto>();
            try
            {
                var user = await _userRepository.GetUserByIdAsync(userId);
                if (user == null)
                {
                    response.Success = false;
                    response.Message = "User not found";
                    return response;
                }

                response.Data = _mapper.Map<UserDto>(user);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<UserDto>> UpdateUserProfileAsync(int userId, UpdateUserDto dto)
        {
            var response = new ServiceResponse<UserDto>();
            try
            {
                var user = await _userRepository.GetUserByIdAsync(userId);
                if (user == null)
                {
                    response.Success = false;
                    response.Message = "User not found";
                    return response;
                }

                _mapper.Map(dto, user);
                user.UpdatedAt = DateTime.UtcNow;
                await _userRepository.UpdateUserAsync(user);
                await _userRepository.SaveChangesAsync();

                response.Data = _mapper.Map<UserDto>(user);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<bool>> ChangePasswordAsync(int userId, ChangePasswordDto dto)
        {
            var response = new ServiceResponse<bool>();
            try
            {
                var user = await _userRepository.GetUserByIdAsync(userId);
                if (user == null || !user.VerifyPassword(dto.CurrentPassword))
                {
                    response.Success = false;
                    response.Message = "Invalid current password";
                    return response;
                }

                user.SetPassword(dto.NewPassword);
                user.UpdatedAt = DateTime.UtcNow;
                await _userRepository.UpdateUserAsync(user);
                await _userRepository.SaveChangesAsync();

                response.Data = true;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<bool>> ForgotPasswordAsync(string email)
        {
            var response = new ServiceResponse<bool>();
            try
            {
                var user = await _userRepository.GetUserByEmailAsync(email);
                if (user == null)
                {
                    response.Success = false;
                    response.Message = "Email not found";
                    return response;
                }

                var resetToken = Guid.NewGuid().ToString();
                // In real app, save resetToken to DB with expiry

                var resetLink = $"https://yourapp.com/reset-password?token={resetToken}";
                var subject = "Password Reset Request";
                var body = $"Click the link to reset your password: {resetLink}";

                await _emailService.SendEmailAsync(email, subject, body);

                response.Data = true;
                response.Message = "Password reset email sent";
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<AuthResponseDto>> RefreshTokenAsync(string refreshToken)
        {
            var response = new ServiceResponse<AuthResponseDto>();
            try
            {
                var storedToken = await _refreshTokenRepository.GetByTokenAsync(refreshToken);
                if (storedToken == null || storedToken.ExpiresAt < DateTime.UtcNow || storedToken.IsRevoked)
                {
                    response.Success = false;
                    response.Message = "Invalid or expired refresh token";
                    return response;
                }

                var user = await _userRepository.GetUserByIdAsync(storedToken.UserId);
                if (user == null)
                {
                    response.Success = false;
                    response.Message = "User not found";
                    return response;
                }

                var newAccessToken = GenerateJwtToken(user);
                var newRefreshToken = GenerateRefreshToken(user);

                // Revoke old token
                storedToken.IsRevoked = true;
                await _refreshTokenRepository.UpdateAsync(storedToken);

                // Add new token
                await _refreshTokenRepository.AddAsync(newRefreshToken);
                await _refreshTokenRepository.SaveChangesAsync();

                response.Data = new AuthResponseDto { AccessToken = newAccessToken, RefreshToken = newRefreshToken.Token, User = _mapper.Map<UserDto>(user) };
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<bool>> LogoutAsync(string refreshToken)
        {
            var response = new ServiceResponse<bool>();
            try
            {
                var storedToken = await _refreshTokenRepository.GetByTokenAsync(refreshToken);
                if (storedToken != null)
                {
                    storedToken.IsRevoked = true;
                    await _refreshTokenRepository.UpdateAsync(storedToken);
                    await _refreshTokenRepository.SaveChangesAsync();
                }

                response.Data = true;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<List<UserDto>>> GetAllUsersAsync()
        {
            var response = new ServiceResponse<List<UserDto>>();
            try
            {
                var users = await _userRepository.GetAllUsersAsync();
                response.Data = _mapper.Map<List<UserDto>>(users);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        private string GenerateJwtToken(User user)
        {
            var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? "default-key-change-in-production";
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // Add roles to claims
            foreach (var role in user.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.Name));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(8), // 8 hours
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private RefreshToken GenerateRefreshToken(User user)
        {
            return new RefreshToken
            {
                Token = Guid.NewGuid().ToString(),
                UserId = user.UserId,
                ExpiresAt = DateTime.UtcNow.AddDays(7), // 7 days
                CreatedAt = DateTime.UtcNow
            };
        }
    }
}
