using JwtAuthAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace JwtAuthAPI.Data
{
    public static class UserSeeder
    {
        public static async Task SeedAsync(AppDbContext context)
        {
            if (await context.Users.AnyAsync()) return;

            var passwordHasher = new PasswordHasher<User>();

            var user = new User
            {
                Username = "admin",
                Role = "Admin"
            };

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword("123456");


            context.Users.Add(user);
            await context.SaveChangesAsync();
        }
    }
}
