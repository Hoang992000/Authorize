using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using User.Manager.Service.Models;

namespace User.Manager.Service.Services
{
    public interface IEmailService
    {
        void SendEmail(Messages message);
    }
}
