using Microsoft.EntityFrameworkCore;
using dvna.Models;

namespace dvna.Data
{
	public class AppDbContext : DbContext
	{
		public AppDbContext(DbContextOptions<AppDbContext> options)
			: base(options) { }

		public DbSet<User> Users { get; set; } = null!;
	}
}
