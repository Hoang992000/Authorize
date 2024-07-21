using MailKit.Net.Smtp;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using User.Manager.Service.Models;

namespace User.Manager.Service.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailConfigurations _emailconfig;
        public EmailService(EmailConfigurations emailconfig)
        {
            _emailconfig = emailconfig;
        }

        public void SendEmail(Messages message)
        {
            var emailMessage = CreateEmailMessage(message);
            Send(emailMessage);
        }
        private MimeMessage CreateEmailMessage(Messages message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress("email", _emailconfig.From));
            emailMessage.To.AddRange(message.To);
            emailMessage.Subject = message.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text) { Text = message.Content };
            
            return emailMessage;
        }
        private void Send(MimeMessage mailMessage)
        {
            var a=_emailconfig.SmtpServer;
            using var client = new SmtpClient();
            try
            {
                client.Connect(_emailconfig.SmtpServer, _emailconfig.Port, true);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate(_emailconfig.UserName, _emailconfig.Password);

                client.Send(mailMessage);
            }
            catch
            {
                //log an error message or throw an exception or both.
                throw new Exception("send mail fail somethings went wrong");
            }
            finally
            {
                client.Disconnect(true);
                client.Dispose();
            }
        }
    }
}
