using CleanDemo.Domain.Domain;

namespace CleanDemo.Application.Interface
{
    public interface IPasswordResetTokenRepository
    {
        Task<PasswordResetToken?> GetByTokenAsync(string token);
        Task AddAsync(PasswordResetToken resetToken);
        Task UpdateAsync(PasswordResetToken resetToken);
        Task DeleteExpiredTokensAsync();
        Task SaveChangesAsync();
    }
}
