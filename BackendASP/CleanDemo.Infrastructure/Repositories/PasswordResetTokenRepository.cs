using CleanDemo.Domain.Domain;
using CleanDemo.Application.Interface;
using CleanDemo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace CleanDemo.Infrastructure.Repositories
{
    public class PasswordResetTokenRepository : IPasswordResetTokenRepository
    {
        private readonly AppDbContext _context;

        public PasswordResetTokenRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<PasswordResetToken?> GetByTokenAsync(string token)
        {
            return await _context.PasswordResetTokens
                .Include(t => t.User)
                .FirstOrDefaultAsync(t => t.Token == token && !t.IsUsed && t.ExpiresAt > DateTime.UtcNow);
        }

        public async Task AddAsync(PasswordResetToken resetToken)
        {
            await _context.PasswordResetTokens.AddAsync(resetToken);
        }

        public async Task UpdateAsync(PasswordResetToken resetToken)
        {
            _context.PasswordResetTokens.Update(resetToken);
            await Task.CompletedTask;
        }

        public async Task DeleteExpiredTokensAsync()
        {
            var expiredTokens = await _context.PasswordResetTokens
                .Where(t => t.ExpiresAt <= DateTime.UtcNow || t.IsUsed)
                .ToListAsync();
            
            _context.PasswordResetTokens.RemoveRange(expiredTokens);
        }

        public async Task SaveChangesAsync()
        {
            await _context.SaveChangesAsync();
        }
    }
}
