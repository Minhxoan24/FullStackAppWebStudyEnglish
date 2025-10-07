using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;

namespace CleanDemo.Application.Service
{
    public class EmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            var smtpSettings = _configuration.GetSection("Smtp");
            var host = smtpSettings["Host"];
            var portString = smtpSettings["Port"] ?? throw new InvalidOperationException("SMTP Port not configured");
            var port = int.Parse(portString);
            var username = smtpSettings["Username"] ?? throw new InvalidOperationException("SMTP Username not configured");
            var password = smtpSettings["Password"];
            var enableSslString = smtpSettings["EnableSsl"] ?? "true";
            var enableSsl = bool.Parse(enableSslString);

            using var client = new SmtpClient(host, port)
            {
                Credentials = new NetworkCredential(username, password),
                EnableSsl = enableSsl
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(username),
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            };
            mailMessage.To.Add(toEmail);

            await client.SendMailAsync(mailMessage);
        }
    }
}
