using System.Net;
using System.Net.Mail;

namespace idp.Services;

public class SendEmailService
{
    private readonly string _smtpHost;
    private readonly int _smtpPort;
    private readonly string _smtpFrom;
    private readonly string _smtpPass;
    private readonly IConfiguration _configuration;
    
    public SendEmailService(IConfiguration configuration)
    {
        _configuration = configuration;
        _smtpHost = _configuration["Smtp:Host"];
        _smtpPort = int.Parse(_configuration["Smtp:Port"]);
        _smtpFrom = _configuration["Smtp:From"];
        _smtpPass = _configuration["Smtp:Pass"];
    }

    public async Task SendEmail(string toEmail, string subject, string body)
    {
        var from = _smtpFrom;

        if (string.IsNullOrWhiteSpace(from))
            throw new InvalidOperationException("SMTP From is not configured");

        using var client = new SmtpClient(_smtpHost, _smtpPort);

        if (!string.IsNullOrWhiteSpace(_smtpPass))
        {
            client.Credentials = new NetworkCredential(_smtpFrom, _smtpPass);
        }

        client.EnableSsl = false; // IMPORTANT for dev => client.EnableSsl = _configuration.GetValue<bool>("Smtp:Ssl");

        var mail = new MailMessage(from, toEmail, subject, body)
        {
            IsBodyHtml = false
        };

        await client.SendMailAsync(mail);
    }
}