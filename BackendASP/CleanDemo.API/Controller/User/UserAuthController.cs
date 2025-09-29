using Microsoft.AspNetCore.Mvc;
using CleanDemo.Application.DTOs;
using CleanDemo.Application.Service.Auth.Register;
using CleanDemo.Application.Service.Auth.Login;
using Microsoft.AspNetCore.Authorization;

namespace CleanDemo.API.Controllers.User
{
    [ApiController]
    [Route("api/user/auth")]
    public class UserAuthController : ControllerBase
    {
        private readonly IRegisterService _registerService;
        private readonly ILoginService _loginService;

        public UserAuthController(IRegisterService registerService, ILoginService loginService)
        {
            _registerService = registerService;
            _loginService = loginService;
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

        // Add more user-specific endpoints here
    }
}
