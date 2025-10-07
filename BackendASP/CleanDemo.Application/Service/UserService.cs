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
        private readonly IPasswordResetTokenRepository _passwordResetTokenRepository;
        private readonly IMapper _mapper;
        private readonly IConfiguration _configuration;
        private readonly EmailService _emailService;

        public UserService(IUserRepository userRepository, IRefreshTokenRepository refreshTokenRepository, IPasswordResetTokenRepository passwordResetTokenRepository, IMapper mapper, IConfiguration configuration, EmailService emailService)
        {
            _userRepository = userRepository;
            _refreshTokenRepository = refreshTokenRepository;
            _passwordResetTokenRepository = passwordResetTokenRepository;
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
                    // Log failed attempt for security monitoring
                    response.Success = false;
                    response.Message = "Invalid current password";
                    return response;
                }

                // Validate new password strength
                if (!IsPasswordStrong(dto.NewPassword))
                {
                    response.Success = false;
                    response.Message = "Password must contain at least 8 characters, including uppercase, lowercase, number and special character";
                    return response;
                }

                user.SetPassword(dto.NewPassword);
                user.UpdatedAt = DateTime.UtcNow;
                await _userRepository.UpdateUserAsync(user);

                // Revoke all refresh tokens for security (force re-login on all devices)
                var userTokens = await _refreshTokenRepository.GetTokensByUserIdAsync(userId);
                foreach (var token in userTokens)
                {
                    token.IsRevoked = true;
                    await _refreshTokenRepository.UpdateAsync(token);
                }

                await _userRepository.SaveChangesAsync();
                await _refreshTokenRepository.SaveChangesAsync();

                response.Data = true;
                response.Message = "Password changed successfully. Please login again on all devices.";
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        private bool IsPasswordStrong(string password)
        {
            if (password.Length < 8) return false;
            
            var hasUpper = password.Any(char.IsUpper);
            var hasLower = password.Any(char.IsLower);
            var hasNumber = password.Any(char.IsDigit);
            var hasSpecial = password.Any(ch => !char.IsLetterOrDigit(ch));
            
            return hasUpper && hasLower && hasNumber && hasSpecial;
        }

        private string GetPasswordResetEmailTemplate(string resetLink)
        {
            // In production, load from file or use a template engine like Razor/Handlebars
            return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>Reset Your Password</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ padding: 30px; background: #f9f9f9; }}
        .button {{ display: inline-block; padding: 15px 30px; background: #4CAF50; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }}
        .footer {{ text-align: center; font-size: 12px; color: #666; margin-top: 20px; padding: 20px; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 15px 0; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>🔐 Password Reset Request</h1>
        </div>
        <div class='content'>
            <p>Hello,</p>
            <p>We received a request to reset your password for your <strong>English Learning</strong> account.</p>
            <p>Click the button below to create a new password:</p>
            <div style='text-align: center;'>
                <a href='{resetLink}' class='button'>Reset My Password</a>
            </div>
            <div class='warning'>
                <p><strong>⏰ Important:</strong> This link will expire in <strong>1 hour</strong> for your security.</p>
            </div>
            <p>If you didn't request this password reset, please ignore this email. Your account remains secure.</p>
            <p><strong>Security tip:</strong> Never share this link with anyone.</p>
            <hr style='margin: 30px 0; border: none; border-top: 1px solid #ddd;'>
            <p style='font-size: 14px; color: #666;'>
                Having trouble clicking the button? Copy and paste this link into your browser:<br>
                <span style='background: #f5f5f5; padding: 8px; border-radius: 4px; word-break: break-all; display: inline-block; margin-top: 5px; font-family: monospace;'>{resetLink}</span>
            </p>
        </div>
        <div class='footer'>
            <p><strong>English Learning App Team</strong></p>
            <p>This is an automated email, please don't reply.</p>
            <p>Need help? Contact us at support@englishlearningapp.com</p>
        </div>
    </div>
</body>
</html>";
        }

        public async Task<ServiceResponse<bool>> ForgotPasswordAsync(string email)
        {
            var response = new ServiceResponse<bool>();
            try
            {
                var user = await _userRepository.GetUserByEmailAsync(email);
                if (user == null)
                {
                    // Don't reveal if email exists or not for security
                    response.Data = true;
                    response.Message = "If the email exists, a password reset link has been sent";
                    return response;
                }

                var resetToken = Guid.NewGuid().ToString();
                var passwordResetToken = new PasswordResetToken
                {
                    Token = resetToken,
                    UserId = user.UserId,
                    ExpiresAt = DateTime.UtcNow.AddHours(1) // Token expires in 1 hour
                };

                await _passwordResetTokenRepository.AddAsync(passwordResetToken);
                await _passwordResetTokenRepository.SaveChangesAsync();

                // In production, use your actual domain
                var frontendUrl = _configuration["Frontend:BaseUrl"] ?? "http://localhost:3000";
                var resetLink = $"{frontendUrl}/reset-password?token={resetToken}";
                var subject = "Reset Your Password - English Learning App";
                
                // Load email template (in production, use a proper template engine)
                var body = GetPasswordResetEmailTemplate(resetLink);

                await _emailService.SendEmailAsync(email, subject, body);

                response.Data = true;
                response.Message = "If the email exists, a password reset link has been sent";
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<bool>> ResetPasswordAsync(ResetPasswordDto dto)
        {
            var response = new ServiceResponse<bool>();
            try
            {
                var resetToken = await _passwordResetTokenRepository.GetByTokenAsync(dto.Token);
                if (resetToken == null)
                {
                    response.Success = false;
                    response.Message = "Invalid or expired reset token";
                    return response;
                }

                var user = resetToken.User ?? await _userRepository.GetUserByIdAsync(resetToken.UserId);
                if (user == null)
                {
                    response.Success = false;
                    response.Message = "User not found";
                    return response;
                }

                // Update password
                user.SetPassword(dto.NewPassword);
                user.UpdatedAt = DateTime.UtcNow;
                await _userRepository.UpdateUserAsync(user);

                // Mark token as used
                resetToken.IsUsed = true;
                await _passwordResetTokenRepository.UpdateAsync(resetToken);

                await _userRepository.SaveChangesAsync();
                await _passwordResetTokenRepository.SaveChangesAsync();

                response.Data = true;
                response.Message = "Password has been reset successfully";
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
