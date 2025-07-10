using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using JwtAuthAPI.Data;
using JwtAuthAPI.DTOs;
using JwtAuthAPI.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCrypt.Net;

namespace JwtAuthAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _config;

        public AuthController(AppDbContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
        }

        // POST: api/auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserLoginDTO dto)
        {
            var exists = await _context.Users.AnyAsync(u => u.Username == dto.Username);
            if (exists) return BadRequest("Username already exists.");

            var user = new User
            {
                Username = dto.Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                Role = "User"
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok(new { message = "User registered successfully." });
        }

        // POST: api/auth/login
        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> Login([FromBody] UserLoginDTO dto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == dto.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                return Unauthorized("Invalid username or password.");

            var token = GenerateJwtToken(user, out DateTime expires);

            var userDto = new UserDTO
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role,
                Token = token,
                Expiration = expires
            };

            return Ok(userDto);
        }

        private string GenerateJwtToken(User user, out DateTime expires)
        {
            var key = _config["JWT_KEY"]!;
            var issuer = _config["JWT_ISSUER"];
            var audience = _config["JWT_AUDIENCE"];
            var minutes = int.Parse(_config["JWT_EXPIRES_IN"]!);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            expires = DateTime.UtcNow.AddMinutes(minutes);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: expires,
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
