using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Transactify.Data;
using Transactify.Models;

namespace Transactify.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserAuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signinManager;
        private readonly string? _jwtKey;
        private readonly string? _jwtIssuer;
        private readonly string? _jwtAudience;
        private readonly int _jwtExpiry;

        public UserAuthController(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signinManager,IConfiguration configuration)
        {
            _userManager = userManager;
            _signinManager = signinManager;
            _jwtKey = configuration["Jwt:Key"];
            _jwtIssuer=configuration["Jwt:Issuer"];
            _jwtAudience= configuration["Jwt:Audience"];
            _jwtExpiry=int.Parse( configuration["Jwt:Expiry"]);
        }

        //baseUrl/api/UserAuth/Register
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if(model == null||string.IsNullOrEmpty(model.Name)
                || string.IsNullOrEmpty(model.Email) 
                || string.IsNullOrEmpty(model.Password))
            {
                return BadRequest(new { result = "Error", message = "Invalid payload" });
            }
           var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                return Conflict("Email already exists");
            }
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                Name = model.Name
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                return Ok(new { result = "Success", message = "User created successfully" });
            }
            return BadRequest(new { result = "Error", message = "User creation failed" });
        }


    }
}
