using IdentityAuth.Models;
using IdentityAuth.Models.Authetication.Login;
using IdentityAuth.Models.Authetication.SignUp;
using IdentityAuth.Models.Entity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using User.Manager.Service.Models;
using User.Manager.Service.Services;

namespace IdentityAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;
        private readonly IEmailService _emailService;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ApplicationDbContext _applicationDbContext;
        public AuthController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IEmailService emailService,
            SignInManager<IdentityUser> signInManager,
            ApplicationDbContext applicationDbContext)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
            _emailService = emailService;
            _signInManager = signInManager;
            _applicationDbContext = applicationDbContext;
        }
        [HttpPost("register")]
        public async Task<IActionResult> register([FromBody] RegisterUser registerUser)
        {
            var userExist = await userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already exists!" });
            }

            //Add the User in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,

            };
            var result = await userManager.CreateAsync(user, registerUser.Password);
            if (!result.Succeeded)
            {
                return BadRequest("somethings went wrong");
            }
            await userManager.AddToRoleAsync(user, "User");
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth", new { token, email = user.Email }, Request.Scheme);
            var message = new Messages(new string[] { user.Email! }, "Confirmation email link", confirmationLink!);
            _emailService.SendEmail(message);

            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = $"User created & Email Sent to {user.Email} SuccessFully" });
        }
        [HttpGet("ConfirmEmail")]
        public async Task<ActionResult> ConfirmEmail(string token, string email)
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return Ok("Email verified Successfully");
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "can not find your email" });
        }
        [Authorize]
        [HttpPost("testMail")]
        public async Task<ActionResult> testMail([FromBody] string content)
        {
            var message = new Messages(new string[] { "buivuhoang12345@gmail.com" }, "test", content);
            _emailService.SendEmail(message);
            return Ok("done!!!");
        }
        [Authorize(Roles = "Admin,HR")]
        [HttpGet("test")]
        public List<string> test()
        {
            return new List<string> { "test", "test1", "test2" };
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginUser loginuser)
        {
            //checking user
            var user = await userManager.FindByEmailAsync(loginuser.Email);
            //checking password
            if (user != null && await userManager.CheckPasswordAsync(user, loginuser.Password))
            {
                var checkConfirmUser = await userManager.IsEmailConfirmedAsync(user);
                if (user.TwoFactorEnabled)
                {
                    await _signInManager.SignOutAsync();
                    await _signInManager.PasswordSignInAsync(user, loginuser.Password, false, true);
                    //var check=await _signInManager.PasswordSignInAsync(user, loginuser.Password, false, true);
                    //if(check.Succeeded)
                    {
                        var token = await userManager.GenerateTwoFactorTokenAsync(user, "Email");

                        var message = new Messages(new string[] { user.Email! }, "OTP Confrimation", token);
                        _emailService.SendEmail(message);

                        return StatusCode(StatusCodes.Status200OK,
                         new Response { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });
                    }
                }
                if (checkConfirmUser)
                {
                    //claimlist creation
                    var authClaims = new List<Claim>
                    {
                         new Claim(ClaimTypes.Name,user.Email),
                         new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };
                    var userRoles = await userManager.GetRolesAsync(user);
                    //add roles
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }
                    //generate the token
                    var jwtToken = genrateToken(authClaims);
                    var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken);
                    var refreshToken = genrateRefreshToken();
                    RefreshToken rf = new RefreshToken(refreshToken, DateTime.UtcNow.AddHours(10), user.Id);
                    await _applicationDbContext.refreshTokens.AddAsync(rf);
                    await _applicationDbContext.SaveChangesAsync();
                    return Ok(new
                    {
                        AccessToken = accessToken,
                        RefreshToken = refreshToken,
                        expiration = jwtToken.ValidTo
                    });
                }
                return BadRequest("Your account has not been verified, please confirm your email before logging in");

            }
            return Unauthorized("email or password invalid");
        }

        [Authorize]
        [HttpPost("turnOn/Off2F")]
        public async Task<IActionResult> turnOnTwoFactor([FromQuery] string email)
        {
            var User = await userManager.FindByEmailAsync(email);
            var state = await userManager.GetTwoFactorEnabledAsync(User);
            var check = await userManager.SetTwoFactorEnabledAsync(User, !state);
            if (check.Succeeded)
            {
                return Ok("turn on succeeded!!");
            }
            return BadRequest("turn on fail");

        }
        [HttpPost("login2F")]
        public async Task<IActionResult> Login2F(string code, string email)
        {
            var user = await userManager.FindByEmailAsync(email);
            var check = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (check != null)
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                var userRoles = await userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var jwtToken = genrateToken(authClaims);
                var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken);
                var refreshToken = genrateRefreshToken();
                RefreshToken rf = new RefreshToken(refreshToken, DateTime.UtcNow.AddHours(10), user.Id);
                await _applicationDbContext.refreshTokens.AddAsync(rf);
                await _applicationDbContext.SaveChangesAsync();
                return Ok(new
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    expiration = jwtToken.ValidTo
                });
            }
            return BadRequest("Invalid Code");
        }

        [HttpPost("forgotPassWord")]
        public async Task<IActionResult> forgotPassWord(string email)
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await userManager.GeneratePasswordResetTokenAsync(user);
                var message = new Messages(new string[] { user.Email }, "reset password token", token);
                _emailService.SendEmail(message);
                return Ok($"reset password token has been sent to your email:{email}");
            }
            return BadRequest("could not send to your email, please check it");
        }
        [HttpPost("resetPass")]
        public async Task<IActionResult> resetPassWord([FromBody] ResetPassword reset)
        {
            var user = await userManager.FindByEmailAsync(reset.Email);
            if (user != null)
            {
                var resetPass = await userManager.ResetPasswordAsync(user, reset.Token, reset.Password);
                if (!resetPass.Succeeded)
                {
                    foreach (var err in resetPass.Errors)
                    {
                        ModelState.AddModelError(err.Code, err.Description);
                    }
                    return BadRequest(ModelState);
                }
                return Ok("reset password succeeded");
            }
            return BadRequest("somethings went wrongs, please try again");
        }
        private JwtSecurityToken genrateToken(List<Claim> lstClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
            var Token = new JwtSecurityToken(
                issuer: configuration["JWT:ValidIssuer"],
                audience: configuration["JWT:ValidAudience"],
                expires: DateTime.UtcNow.AddMinutes(20),
                claims: lstClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return Token;
        }
        private string genrateRefreshToken()
        {
            var random = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);

                return Convert.ToBase64String(random);
            }
        }
        //[Authorize]
        //[HttpPost("renew-Token")]
        //public async Task<IActionResult> renewToken(TokenModel token)
        //{
        //    var jwtTokenHandler=new JwtSecurityTokenHandler();
        //    var secretKey= new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
        //}
    }
}
