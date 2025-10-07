using CleanDemo.Application.Interface;
using CleanDemo.Domain.Domain;
using CleanDemo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace CleanDemo.Infrastructure.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly AppDbContext _context;

        public UserRepository(AppDbContext context) => _context = context;

        public async Task<User?> GetUserByIdAsync(int id) =>
            await _context.Users.Include(u => u.Roles).FirstOrDefaultAsync(u => u.UserId == id);

        public async Task<User?> GetUserByEmailAsync(string email) =>
            await _context.Users.Include(u => u.Roles).FirstOrDefaultAsync(u => u.Email == email);

        public async Task<List<User>> GetAllUsersAsync() =>
            await _context.Users.Include(u => u.Roles).ToListAsync();

        public async Task AddUserAsync(User user) => await _context.Users.AddAsync(user);

        public async Task UpdateUserAsync(User user)
        {
            _context.Users.Update(user);
            await Task.CompletedTask;
        }

        public async Task DeleteUserAsync(int id)
        {
            var user = await GetUserByIdAsync(id);
            if (user != null) _context.Users.Remove(user);
        }

        public async Task SaveChangesAsync() => await _context.SaveChangesAsync();
    }
}
