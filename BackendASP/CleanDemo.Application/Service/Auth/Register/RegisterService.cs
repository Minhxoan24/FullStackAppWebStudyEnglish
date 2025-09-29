using CleanDemo.Application.DTOs;
using CleanDemo.Application.Common;
using CleanDemo.Application.Interface;
using CleanDemo.Domain.Domain;
using AutoMapper;

namespace CleanDemo.Application.Service.Auth.Register
{
    public class RegisterService : IRegisterService
    {
        private readonly IUserRepository _userRepository;
        private readonly IMapper _mapper;

        public RegisterService(IUserRepository userRepository, IMapper mapper)
        {
            _userRepository = userRepository;
            _mapper = mapper;
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
    }
}
