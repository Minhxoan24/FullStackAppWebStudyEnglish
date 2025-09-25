using CleanDemo.Application.DTOs;
using CleanDemo.Application.Interface;
using CleanDemo.Domain.Domain;
using CleanDemo.Application.Common;
using CleanDemo.Application.Validators;
using AutoMapper;

namespace CleanDemo.Application.Service
{
    public class CourseService : ICourseService
    {
        private readonly ICourseRepository _courseRepository;
        private readonly IMapper _mapper;

        public CourseService(ICourseRepository courseRepository, IMapper mapper)
        {
            _courseRepository = courseRepository;
            _mapper = mapper;
        }

        public async Task<ServiceResponse<IEnumerable<CourseDto>>> GetAllCoursesAsync()
        {
            var response = new ServiceResponse<IEnumerable<CourseDto>>();
            try
            {
                var courses = await _courseRepository.GetAllCoursesAsync();
                response.Data = _mapper.Map<IEnumerable<CourseDto>>(courses);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<CourseDto>> GetCourseByIdAsync(int id)
        {
            var response = new ServiceResponse<CourseDto>();
            try
            {
                var course = await _courseRepository.GetCourseByIdAsync(id);
                if (course == null)
                {
                    response.Success = false;
                    response.Message = $"Course with ID {id} not found";
                    return response;
                }

                response.Data = _mapper.Map<CourseDto>(course);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<CourseDto>> CreateCourseAsync(CreateCourseDto createCourseDto)
        {
            var response = new ServiceResponse<CourseDto>();
            try
            {
                var course = _mapper.Map<Course>(createCourseDto);

                await _courseRepository.AddCourseAsync(course);
                await _courseRepository.SaveChangesAsync();

                response.Data = _mapper.Map<CourseDto>(course);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<CourseDto>> UpdateCourseAsync(int id, UpdateCourseDto updateCourseDto)
        {
            var response = new ServiceResponse<CourseDto>();
            try
            {
                if (id <= 0) throw new ArgumentException("Course ID must be greater than 0");

                var existingCourse = await _courseRepository.GetCourseByIdAsync(id);
                if (existingCourse == null)
                {
                    response.Success = false;
                    response.Message = $"Course with ID {id} not found";
                    return response;
                }

                existingCourse.Name = updateCourseDto.Name ?? existingCourse.Name;
                existingCourse.Description = updateCourseDto.Description ?? existingCourse.Description;
                existingCourse.Level = updateCourseDto.Level ?? existingCourse.Level;

                await _courseRepository.UpdateCourseAsync(existingCourse);
                await _courseRepository.SaveChangesAsync();

                response.Data = _mapper.Map<CourseDto>(existingCourse);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<bool>> DeleteCourseAsync(int id)
        {
            var response = new ServiceResponse<bool>();
            try
            {
                var existingCourse = await _courseRepository.GetCourseByIdAsync(id);
                if (existingCourse == null)
                {
                    response.Success = false;
                    response.Message = $"Course with ID {id} not found";
                    return response;
                }

                await _courseRepository.DeleteCourseAsync(id);
                await _courseRepository.SaveChangesAsync();
                response.Data = true;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<CourseDto>> PublishCourseAsync(int courseId)
        {
            var response = new ServiceResponse<CourseDto>();
            try
            {
                var course = await _courseRepository.GetCourseByIdAsync(courseId);
                if (course == null)
                {
                    response.Success = false;
                    response.Message = "Course not found";
                    return response;
                }

                course.Publish();

                await _courseRepository.UpdateCourseAsync(course);
                await _courseRepository.SaveChangesAsync();

                response.Data = _mapper.Map<CourseDto>(course);
            }
            catch (InvalidOperationException ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = ex.Message;
            }
            return response;
        }

        public async Task<ServiceResponse<CourseDto>> ArchiveCourseAsync(int courseId)
        {
            var response = new ServiceResponse<CourseDto>();
            try
            {
                var course = await _courseRepository.GetCourseByIdAsync(courseId);
                if (course == null)
                {
                    response.Success = false;
                    response.Message = "Course not found";
                    return response;
                }

                course.Archive();

                await _courseRepository.UpdateCourseAsync(course);
                await _courseRepository.SaveChangesAsync();

                response.Data = _mapper.Map<CourseDto>(course);
            }
            catch (InvalidOperationException ex)
            {
                response.Success = false;
                response.Message = ex.Message;
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
