using Microsoft.EntityFrameworkCore;
using SocialLoginApplicationMVC.Models;

namespace SocialLoginApplicationMVC.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        public DbSet<ApplicationUser> Users { get; set; }
    }
}
