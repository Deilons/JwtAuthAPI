using JwtAuthAPI.Data;
using JwtAuthAPI.DTOs;
using JwtAuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;

        public UserController(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // POST /register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserDTO request)
        {
            var existingUser = await _context.Users.AnyAsync(u => u.Username == request.Username);
            if (existingUser)
                return BadRequest("Username already exists");

            var user = new User
            {
                Username = request.Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Token), // Usamos Token como contraseña por ahora
                Role = request.Role ?? "User"
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok("User registered");
        }

        // POST /login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                return Unauthorized("Invalid credentials");

            var token = GenerateJwt(user, out DateTime expires);

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

        // GET /me
        [Authorize]
        [HttpGet("me")]
        public async Task<IActionResult> Me()
        {
            var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);

            if (user == null) return NotFound();

            return Ok(new UserDTO
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role
            });
        }

        // JWT Token Generator
        private string GenerateJwt(User user, out DateTime expiration)
        {
            var key = _configuration["JWT_KEY"]!;
            var issuer = _configuration["JWT_ISSUER"];
            var audience = _configuration["JWT_AUDIENCE"];
            var minutes = int.Parse(_configuration["JWT_EXPIRES_IN"] ?? "60");

            expiration = DateTime.UtcNow.AddMinutes(minutes);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var credentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                SecurityAlgorithms.HmacSha256
            );

            var token = new JwtSecurityToken(
                issuer,
                audience,
                claims,
                expires: expiration,
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
