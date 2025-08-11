namespace SocialLoginApplicationMVC.Models
{
    public class ApplicationUser
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string? Name { get; set; }
        public string? Provider { get; set; } // "Google"
        public string? ProviderId { get; set; }
        public string? Picture { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string? PasswordHash { get; set; }
    }
}
