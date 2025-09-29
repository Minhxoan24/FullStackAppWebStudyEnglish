using CleanDemo.Domain.Domain;

namespace CleanDemo.Application.Interface
{
    public interface IRefreshTokenRepository
    {
        Task<RefreshToken?> GetByTokenAsync(string token);
        Task AddAsync(RefreshToken refreshToken);
        Task UpdateAsync(RefreshToken refreshToken);
        Task DeleteAsync(string token);
        Task SaveChangesAsync();
    }
}
