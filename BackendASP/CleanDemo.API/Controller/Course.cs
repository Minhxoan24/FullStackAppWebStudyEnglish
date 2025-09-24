using Microsoft.AspNetCore.Mvc;
using CleanDemo.Application.Interface;
using CleanDemo.Application.DTOs;

namespace CleanDemo.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CourseController : ControllerBase
    {
        private readonly ICourseService _courseService;

        public CourseController(ICourseService courseService)
        {
            _courseService = courseService;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<CourseDto>>> GetAllCourses()
        {
            var result = await _courseService.GetAllCoursesAsync();
            if (!result.Success) return StatusCode(500, new { message = result.Message });
            return Ok(result.Data);
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<CourseDto>> GetCourseById(int id)
        {
            var result = await _courseService.GetCourseByIdAsync(id);
            if (!result.Success) return NotFound(new { message = result.Message });
            return Ok(result.Data);
        }

        [HttpPost]
        public async Task<ActionResult<CourseDto>> CreateCourse(CreateCourseDto createCourseDto)
        {
            var result = await _courseService.CreateCourseAsync(createCourseDto);
            if (!result.Success) return BadRequest(new { message = result.Message });
            return CreatedAtAction(nameof(GetCourseById), new { id = result.Data!.Id }, result.Data);
        }

        [HttpPut("{id}")]
        public async Task<ActionResult<CourseDto>> UpdateCourse(int id, UpdateCourseDto updateCourseDto)
        {
            var result = await _courseService.UpdateCourseAsync(id, updateCourseDto);
            if (!result.Success) return NotFound(new { message = result.Message });
            return Ok(result.Data);
        }
        // endpoint delete

        [HttpDelete("{id}")]
        public async Task<ActionResult> DeleteCourse(int id)
        {
            var result = await _courseService.DeleteCourseAsync(id);
            if (!result.Success) return NotFound(new { message = result.Message });
            return NoContent();
        }

        //  Publish Course endpoint
        [HttpPost("{id}/publish")]
        public async Task<ActionResult<CourseDto>> PublishCourse(int id)
        {
            var result = await _courseService.PublishCourseAsync(id);
            
            if (!result.Success)
                return BadRequest(new { message = result.Message });
                
            return Ok(result.Data);
        }
    }
}
