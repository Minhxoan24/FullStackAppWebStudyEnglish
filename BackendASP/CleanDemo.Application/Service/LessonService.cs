using CleanDemo.Application.DTOs;
using CleanDemo.Application.Interface;
using CleanDemo.Domain.Domain;
using CleanDemo.Application.Common;
using CleanDemo.Application.Validators;
using AutoMapper;

namespace CleanDemo.Application.Service
{
    public class LessonService : ILessonService
    {
        private readonly ILessonRepository _lessonRepository;
        private readonly ICourseRepository _courseRepository;
        private readonly IMapper _mapper;

        public LessonService(ILessonRepository lessonRepository, ICourseRepository courseRepository, IMapper mapper)
        {
            _lessonRepository = lessonRepository;
            _courseRepository = courseRepository;
            _mapper = mapper;
        }

        public async Task<ServiceResponse<List<LessonDto>>> GetAllLessonsAsync()
        {
            var response = new ServiceResponse<List<LessonDto>>();
            try
            {
                var lessons = await _lessonRepository.GetAllLessonsAsync();
                response.Data = _mapper.Map<List<LessonDto>>(lessons);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<LessonDto>> GetLessonByIdAsync(int id)
        {
            var response = new ServiceResponse<LessonDto>();
            try
            {
                var lesson = await _lessonRepository.GetLessonByIdAsync(id);
                if (lesson == null)
                {
                    response.Success = false;
                    response.Message = $"Lesson with ID {id} not found";
                    return response;
                }

                response.Data = _mapper.Map<LessonDto>(lesson);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<LessonDto>> CreateLessonAsync(CreateLessonDto createLessonDto)
        {
            var response = new ServiceResponse<LessonDto>();
            try
            {
                var course = await _courseRepository.GetCourseByIdAsync(createLessonDto.CourseId);
                if (course == null)
                {
                    response.Success = false;
                    response.Message = $"Course with ID {createLessonDto.CourseId} not found";
                    return response;
                }

                var lesson = _mapper.Map<Lesson>(createLessonDto);
                await _lessonRepository.AddLessonAsync(lesson);
                await _lessonRepository.SaveChangesAsync();

                response.Data = _mapper.Map<LessonDto>(lesson);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<LessonDto>> UpdateLessonAsync(int id, UpdateLessonDto updateLessonDto)
        {
            var response = new ServiceResponse<LessonDto>();
            try
            {
                var existingLesson = await _lessonRepository.GetLessonByIdAsync(id);
                if (existingLesson == null)
                {
                    response.Success = false;
                    response.Message = $"Lesson with ID {id} not found";
                    return response;
                }

                if (!string.IsNullOrWhiteSpace(updateLessonDto.Title))
                    existingLesson.Title = updateLessonDto.Title;
                if (!string.IsNullOrWhiteSpace(updateLessonDto.Content))
                    existingLesson.Content = updateLessonDto.Content;
                if (updateLessonDto.CourseId.HasValue && updateLessonDto.CourseId.Value > 0)
                    existingLesson.CourseId = updateLessonDto.CourseId.Value;

                await _lessonRepository.UpdateLessonAsync(existingLesson);
                await _lessonRepository.SaveChangesAsync();

                response.Data = _mapper.Map<LessonDto>(existingLesson);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<bool>> DeleteLessonAsync(int id)
        {
            var response = new ServiceResponse<bool>();
            try
            {
                var existingLesson = await _lessonRepository.GetLessonByIdAsync(id);
                if (existingLesson == null)
                {
                    response.Success = false;
                    response.Message = $"Lesson with ID {id} not found";
                    return response;
                }

                await _lessonRepository.DeleteLessonAsync(id);
                await _lessonRepository.SaveChangesAsync();
                response.Data = true;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<List<LessonDto>>> GetLessonsByCourseIdAsync(int courseId)
        {
            var response = new ServiceResponse<List<LessonDto>>();
            try
            {
                var lessons = await _lessonRepository.GetLessonsByCourseIdAsync(courseId);
                response.Data = _mapper.Map<List<LessonDto>>(lessons);
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
