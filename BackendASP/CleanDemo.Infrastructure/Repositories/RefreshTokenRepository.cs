using CleanDemo.Application.Interface;
using CleanDemo.Domain.Domain;
using CleanDemo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace CleanDemo.Infrastructure.Repositories
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly AppDbContext _context;

        public RefreshTokenRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<RefreshToken?> GetByTokenAsync(string token)
        {
            return await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);
        }

        public async Task<List<RefreshToken>> GetTokensByUserIdAsync(int userId)
        {
            return await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && !rt.IsRevoked)
                .ToListAsync();
        }

        public async Task AddAsync(RefreshToken refreshToken)
        {
            await _context.RefreshTokens.AddAsync(refreshToken);
        }

        public async Task UpdateAsync(RefreshToken refreshToken)
        {
            _context.RefreshTokens.Update(refreshToken);
            await Task.CompletedTask;
        }

        public async Task DeleteAsync(string token)
        {
            var tokenEntity = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);
            if (tokenEntity != null)
            {
                _context.RefreshTokens.Remove(tokenEntity);
            }
        }

        public async Task SaveChangesAsync()
        {
            await _context.SaveChangesAsync();
        }
    }
}
