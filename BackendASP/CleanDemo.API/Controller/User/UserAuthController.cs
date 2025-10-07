using Microsoft.AspNetCore.Mvc;
using CleanDemo.Application.DTOs;
using CleanDemo.Application.Service.Auth.Register;
using CleanDemo.Application.Service.Auth.Login;
using Microsoft.AspNetCore.Authorization;
using CleanDemo.Application.Interface;
using System.IdentityModel.Tokens.Jwt;

namespace CleanDemo.API.Controllers.User
{
    [ApiController]
    [Route("api/user/auth")]
    public class UserAuthController : ControllerBase
    {
        private readonly IRegisterService _registerService;
        private readonly ILoginService _loginService;
        private readonly IUserService _userService;

        public UserAuthController(IRegisterService registerService, ILoginService loginService, IUserService userService)
        {
            _registerService = registerService;
            _loginService = loginService;
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto dto)
        {
            var result = await _registerService.RegisterUserAsync(dto);
            if (!result.Success) return BadRequest(new { message = result.Message });
            return CreatedAtAction(nameof(Register), result.Data);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginUserDto dto)
        {
            var result = await _loginService.LoginUserAsync(dto);
            if (!result.Success) return Unauthorized(new { message = result.Message });
            return Ok(result.Data);
        }

        [Authorize]
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userIdClaim = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
                return Unauthorized(new { message = "Invalid token" });

            var result = await _userService.GetUserProfileAsync(userId);
            if (!result.Success) return NotFound(new { message = result.Message });
            return Ok(result.Data);
        }

        [Authorize]
        [HttpPut("profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateUserDto dto)
        {
            var userIdClaim = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
                return Unauthorized(new { message = "Invalid token" });

            var result = await _userService.UpdateUserProfileAsync(userId, dto);
            if (!result.Success) return BadRequest(new { message = result.Message });
            return Ok(result.Data);
        }

        [Authorize]
        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            var userIdClaim = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
                return Unauthorized(new { message = "Invalid token" });

            var result = await _userService.ChangePasswordAsync(userId, dto);
            if (!result.Success) return BadRequest(new { message = result.Message });
            return Ok(new { message = "Password changed successfully" });
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
        {
            var result = await _userService.ForgotPasswordAsync(dto.Email);
            if (!result.Success) return BadRequest(new { message = result.Message });
            return Ok(new { message = result.Message });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            var result = await _userService.ResetPasswordAsync(dto);
            if (!result.Success) return BadRequest(new { message = result.Message });
            return Ok(new { message = result.Message });
        }

        // Add more user-specific endpoints here
    }
}
