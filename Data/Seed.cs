using dvna.Models;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity;

namespace dvna.Data
{
    public static class Seed
    {
        public static void Init(IApplicationBuilder app)
        {
            using (IServiceScope scope = app.ApplicationServices.CreateScope())
            {
                AppDbContext db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                // Supprime la base existante (juste pour le lab !)
                db.Database.EnsureDeleted();         // <--- Ajoute cette ligne temporairement

                // Recrée la base
                db.Database.EnsureCreated();

                // Seed initial
                if (!db.Users.Any())
                {
                    var hasher = new PasswordHasher<User>();

                    var admin = new User { Username = "admin" };
                    admin.Password = hasher.HashPassword(admin, "admin123");

                    var user = new User { Username = "user" };
                    user.Password = hasher.HashPassword(user, "password123");

                    db.Users.AddRange(admin, user);
                    db.SaveChanges();
                }

            }

        }
    }
}
