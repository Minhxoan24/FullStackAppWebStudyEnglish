using CleanDemo.Domain.Domain;

namespace CleanDemo.Application.Service.Auth.Token
{
    public interface ITokenService
    {
        string GenerateAccessToken(User user);
        RefreshToken GenerateRefreshToken(User user);
    }
}
