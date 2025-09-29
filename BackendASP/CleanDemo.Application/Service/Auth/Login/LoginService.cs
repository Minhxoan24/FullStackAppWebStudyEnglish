using CleanDemo.Application.DTOs;
using CleanDemo.Application.Common;
using CleanDemo.Application.Interface;
using CleanDemo.Domain.Domain;
using AutoMapper;
using Microsoft.Extensions.Configuration;
using CleanDemo.Application.Service.Auth.Token;

namespace CleanDemo.Application.Service.Auth.Login
{
    public class LoginService : ILoginService
    {
        private readonly IUserRepository _userRepository;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly IMapper _mapper;
        private readonly ITokenService _tokenService;

        public LoginService(IUserRepository userRepository, IRefreshTokenRepository refreshTokenRepository, IMapper mapper, ITokenService tokenService)
        {
            _userRepository = userRepository;
            _refreshTokenRepository = refreshTokenRepository;
            _mapper = mapper;
            _tokenService = tokenService;
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

                var accessToken = _tokenService.GenerateAccessToken(user);
                var refreshToken = _tokenService.GenerateRefreshToken(user);

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
    }
}
