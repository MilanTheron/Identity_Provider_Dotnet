using System.Net;
using System.Net.Mail;

namespace idp.Services;

public class SendEmailService
{
    private readonly string _smtpHost;
    private readonly int _smtpPort;
    private readonly string _smtpUser;
    private readonly string _smtpPass;
    private readonly IConfiguration _configuration;
    
    public SendEmailService(IConfiguration configuration)
    {
        _configuration = configuration;
        _smtpHost = _configuration["Smtp:Host"];
        _smtpPort = int.Parse(_configuration["Smtp:Port"]);
        _smtpUser = _configuration["Smtp:User"];
        _smtpPass = _configuration["Smtp:Pass"];
    }

    public async Task SendEmail(string toEmail, string subject, string body)
    {
        using var client = new SmtpClient(_smtpHost, _smtpPort)
        {
            Credentials = new NetworkCredential(_smtpUser, _smtpPass),
            EnableSsl = true
        };

        var mail = new MailMessage(_smtpUser, toEmail, subject, body);
        mail.IsBodyHtml = true;
        await client.SendMailAsync(mail);
    }
}