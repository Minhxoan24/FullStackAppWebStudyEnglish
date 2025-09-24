using Microsoft.AspNetCore.Mvc;
using CleanDemo.Application.Interface;
using CleanDemo.Application.DTOs;

namespace CleanDemo.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LessonController : ControllerBase
    {
        private readonly ILessonService _lessonService;

        public LessonController(ILessonService lessonService)
        {
            _lessonService = lessonService;
        }

        [HttpGet]
        public async Task<ActionResult<List<LessonDto>>> GetAllLessons()
        {
            var result = await _lessonService.GetAllLessonsAsync();
            if (!result.Success) return StatusCode(500, new { message = result.Message });
            return Ok(result.Data);
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<LessonDto>> GetLessonById(int id)
        {
            var result = await _lessonService.GetLessonByIdAsync(id);
            if (!result.Success) return NotFound(new { message = result.Message });
            return Ok(result.Data);
        }

        [HttpGet("course/{courseId}")]
        public async Task<ActionResult<List<LessonDto>>> GetLessonsByCourseId(int courseId)
        {
            var result = await _lessonService.GetLessonsByCourseIdAsync(courseId);
            if (!result.Success) return BadRequest(new { message = result.Message });
            return Ok(result.Data);
        }

        [HttpPost]
        public async Task<ActionResult<LessonDto>> CreateLesson(CreateLessonDto createLessonDto)
        {
            var result = await _lessonService.CreateLessonAsync(createLessonDto);
            if (!result.Success) return BadRequest(new { message = result.Message });
            return CreatedAtAction(nameof(GetLessonById), new { id = result.Data!.Id }, result.Data);
        }

        [HttpPut("{id}")]
        public async Task<ActionResult<LessonDto>> UpdateLesson(int id, UpdateLessonDto updateLessonDto)
        {
            var result = await _lessonService.UpdateLessonAsync(id, updateLessonDto);
            if (!result.Success) return NotFound(new { message = result.Message });
            return Ok(result.Data);
        }

        [HttpDelete("{id}")]
        public async Task<ActionResult> DeleteLesson(int id)
        {
            var result = await _lessonService.DeleteLessonAsync(id);
            if (!result.Success) return NotFound(new { message = result.Message });
            return NoContent();
        }
    }
}
