using CleanDemo.Application.DTOs;
using CleanDemo.Application.Common;

namespace CleanDemo.Application.Service.Auth.Login
{
    public interface ILoginService
    {
        Task<ServiceResponse<AuthResponseDto>> LoginUserAsync(LoginUserDto dto);
    }
}
