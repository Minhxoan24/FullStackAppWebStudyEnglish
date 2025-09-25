using CleanDemo.Domain.Domain;
namespace CleanDemo.Application.Interface

{
    public interface IUser
    {
        Task<User> GetUserById(int id);
        Task<List<User>> GetAllUsers();
        Task<User> CreateUser(User user);
        Task<User> UpdateUser(int id, User user);
        Task<bool> DeleteUser(int id);
    }
}
    