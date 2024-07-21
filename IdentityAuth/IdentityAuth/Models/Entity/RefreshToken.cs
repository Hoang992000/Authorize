using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityAuth.Models.Entity
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; }
        public DateTime ExpiredTime { get; set; }
        public string UserId { get; set; }

        [ForeignKey("UserId")]
        public IdentityUser User { get; set; }

        public RefreshToken(string token, DateTime expiredTime, string userId)
        {
            Token = token;
            ExpiredTime = expiredTime;
            UserId = userId;
        }
    }
}
