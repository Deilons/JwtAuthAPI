namespace JwtAuthAPI.DTOs
{
    public class UserDTO
    {
        public int Id { get; set; }

        public string Username { get; set; } = null!;

        public string Role { get; set; } = "User";

        public string? Token { get; set; }

        // for the DTO dont include the password
        public DateTime? Expiration { get; set; }

       
    }
}
