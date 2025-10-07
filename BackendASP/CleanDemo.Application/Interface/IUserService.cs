using CleanDemo.Application.DTOs;
using CleanDemo.Application.Common;

namespace CleanDemo.Application.Interface
{
    public interface IUserService
    {
        Task<ServiceResponse<UserDto>> RegisterUserAsync(RegisterUserDto dto);
        Task<ServiceResponse<AuthResponseDto>> LoginUserAsync(LoginUserDto dto);
        Task<ServiceResponse<UserDto>> GetUserProfileAsync(int userId);
        Task<ServiceResponse<UserDto>> UpdateUserProfileAsync(int userId, UpdateUserDto dto);
        Task<ServiceResponse<bool>> ChangePasswordAsync(int userId, ChangePasswordDto dto);
        Task<ServiceResponse<bool>> ForgotPasswordAsync(string email);
        Task<ServiceResponse<bool>> ResetPasswordAsync(ResetPasswordDto dto);
        Task<ServiceResponse<AuthResponseDto>> RefreshTokenAsync(string refreshToken);
        Task<ServiceResponse<bool>> LogoutAsync(string refreshToken);
        Task<ServiceResponse<List<UserDto>>> GetAllUsersAsync();
    }
}
