using System.Collections.Concurrent;

namespace CleanDemo.Application.Service
{
    public class SecurityService
    {
        private readonly ConcurrentDictionary<string, List<DateTime>> _passwordResetAttempts = new();
        private readonly ConcurrentDictionary<string, List<DateTime>> _loginAttempts = new();

        public bool IsPasswordResetAllowed(string email)
        {
            var attempts = _passwordResetAttempts.GetOrAdd(email, _ => new List<DateTime>());
            
            // Remove attempts older than 15 minutes
            var now = DateTime.UtcNow;
            attempts.RemoveAll(attempt => now.Subtract(attempt).TotalMinutes > 15);
            
            // Allow max 5 attempts per 15 minutes
            return attempts.Count < 5;
        }

        public void RecordPasswordResetAttempt(string email)
        {
            var attempts = _passwordResetAttempts.GetOrAdd(email, _ => new List<DateTime>());
            attempts.Add(DateTime.UtcNow);
        }

        public bool IsLoginAllowed(string email)
        {
            var attempts = _loginAttempts.GetOrAdd(email, _ => new List<DateTime>());
            
            // Remove attempts older than 15 minutes
            var now = DateTime.UtcNow;
            attempts.RemoveAll(attempt => now.Subtract(attempt).TotalMinutes > 15);
            
            // Allow max 10 failed login attempts per 15 minutes
            return attempts.Count < 10;
        }

        public void RecordFailedLoginAttempt(string email)
        {
            var attempts = _loginAttempts.GetOrAdd(email, _ => new List<DateTime>());
            attempts.Add(DateTime.UtcNow);
        }

        public void ClearLoginAttempts(string email)
        {
            _loginAttempts.TryRemove(email, out _);
        }
    }
}
