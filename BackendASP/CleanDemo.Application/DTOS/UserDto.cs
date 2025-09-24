using System.ComponentModel.DataAnnotations;

namespace CleanDemo.Application.DTOS
{
    public class CreateUserDto
    {
        public string SureName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        private string PassWord { get; set; }
        private string ConfirmPassword { get; set; }
        private string PhoneNumber { get; set; }
    }
    public class UpdateUserDto
    {
        public string? SureName { get; set; }
        public string? LastName { get; set; }

        private string? PassWord { get; set; }
        private string? ConfirmPassword { get; set; }


    }
    public class UserDto
    {
        public int UserId { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }

    }
    public class DeleteUserDto
    {
        public int UserId { get; set; }
    }
}
