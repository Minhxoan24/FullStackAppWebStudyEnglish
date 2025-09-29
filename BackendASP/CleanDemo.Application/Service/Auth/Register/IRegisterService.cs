using CleanDemo.Application.DTOs;
using CleanDemo.Application.Common;

namespace CleanDemo.Application.Service.Auth.Register
{
    public interface IRegisterService
    {
        Task<ServiceResponse<UserDto>> RegisterUserAsync(RegisterUserDto dto);
    }
}
