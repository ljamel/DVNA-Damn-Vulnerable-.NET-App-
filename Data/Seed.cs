using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using dvna.Models;

namespace dvna.Data
{
	public static class Seed
	{
		public static void Init(IApplicationBuilder app)
		{
			using (var scope = app.ApplicationServices.CreateScope())
			{
				var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

				// ⚠️ Supprime la base existante (juste pour le lab !)
				db.Database.EnsureDeleted();         // <--- Ajoute cette ligne temporairement

				// Recrée la base
				db.Database.EnsureCreated();

				// Seed initial
				if (!db.Users.Any())
				{
					db.Users.AddRange(
						new User { Username = "admin", Password = "admiIIjijdeeziUUHUJHn123I" },
						new User { Username = "user", Password = "password123" }
					);
					db.SaveChanges();
				}
			}

		}
	}
}
