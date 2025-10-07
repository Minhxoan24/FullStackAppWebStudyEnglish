using Microsoft.AspNetCore.Mvc;
using CleanDemo.Application.Interface;
using CleanDemo.Application.DTOs;
using Microsoft.AspNetCore.Authorization;

namespace CleanDemo.API.Controllers.Admin
{
    [ApiController]
    [Route("api/admin/auth")]
    [Authorize(Policy = "AdminOnly")]
    public class AdminAuthController : ControllerBase
    {
        private readonly IUserService _userService;

        public AdminAuthController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpGet("users")]
        public async Task<IActionResult> GetAllUsers()
        {
            var result = await _userService.GetAllUsersAsync();
            if (!result.Success) return BadRequest(new { message = result.Message });
            return Ok(result.Data);
        }

        [HttpPut("users/{id}/role")]
        public async Task<IActionResult> UpdateUserRole(int id, [FromBody] UpdateUserRoleDto dto)
        {
            // Implement update role logic
            await Task.CompletedTask;
            return Ok(new { message = "Role updated" });
        }

        // Add more admin endpoints
    }
}
