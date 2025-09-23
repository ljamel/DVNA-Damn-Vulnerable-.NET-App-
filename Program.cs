// ================================
// Projet : DVNA (Damn Vulnerable .NET App)
// Auteur : Lamri [aka ingenius]
// Date : 2025
// Description : Application web ASP.NET Core volontairement vulnérable pour l’apprentissage de la sécurité
// ================================
// ajout du plugin sqlite dotnet add package Microsoft.EntityFrameworkCore.Sqlite avant dotnet run

using Microsoft.AspNetCore.StaticFiles;
using dvna.Data;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// ➕ Ajout de SQLite
builder.Services.AddDbContext<AppDbContext>(options =>
	options.UseSqlite("Data Source=lab.db"));

var uploadsDir = Path.Combine(Directory.GetCurrentDirectory(), "uploads");
Directory.CreateDirectory(uploadsDir);

// Ajouter les services MVC
builder.Services.AddControllersWithViews();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
	app.UseExceptionHandler("/Home/Error");
	app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
	name: "xss",
	pattern: "Xss",
	defaults: new { controller = "Home", action = "Xss" });

app.MapControllerRoute(
	name: "injectcommande",
	pattern: "Injectcommande",
	defaults: new { controller = "Home", action = "Injectcommande" });

app.MapControllerRoute(
	name: "SqlInjection",
	pattern: "SqlInjection",
	defaults: new { controller = "Home", action = "SqlInjection" });

app.MapControllerRoute(
	name: "LoginSecure",
	pattern: "LoginSecure",
	defaults: new { controller = "Home", action = "LoginSecure" });

app.MapControllerRoute(
	name: "Auth",
	pattern: "Auth",
	defaults: new { controller = "Home", action = "Auth" });

app.MapControllerRoute(
	name: "default",
	pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapPost("/upload", async (HttpRequest req) =>
{
	if (!req.HasFormContentType)
		return Results.BadRequest("form-data attendu.");

	var form = await req.ReadFormAsync();
	var file = form.Files["file"];
	if (file == null)
		return Results.BadRequest("fichier manquant (champ 'file').");

	var providedName = form["filename"].FirstOrDefault() ?? file.FileName ?? "unnamed";

	// === VULN : on combine directement sans normalisation (intentionnel)
	var destPath = Path.Combine(uploadsDir, providedName);

	// Create directory if user supplied subfolder in name (still vuln: allows ../ if providedName has traversal sequences)
	Directory.CreateDirectory(Path.GetDirectoryName(destPath) ?? uploadsDir);

	await using (var fs = File.Create(destPath))
	{
		await file.CopyToAsync(fs);
	}

	var url = $"/view?name={Uri.EscapeDataString(providedName)}";
	return Results.Ok(new { savedAs = providedName, url });
});

app.MapGet("/view", (string name, HttpResponse response) =>
{
	if (string.IsNullOrWhiteSpace(name))
		return Results.BadRequest("name manquant.");

	// === VULN: on combine directement (conserve la vulnérabilité si tu veux)
	var path = Path.Combine(uploadsDir, name);

	if (!File.Exists(path))
		return Results.NotFound("fichier introuvable.");

	// Tenter de détecter le content-type par extension
	var provider = new FileExtensionContentTypeProvider();
	if (!provider.TryGetContentType(path, out var contentType))
	{
		// Fallbacks utiles pour CTF : forcer les types connus
		var ext = Path.GetExtension(path)?.ToLowerInvariant() ?? "";
		contentType = ext switch
		{
			".png" => "image/png",
			".jpg" => "image/jpeg",
			".jpeg" => "image/jpeg",
			".gif" => "image/gif",
			".svg" => "image/svg+xml",
			".webp" => "image/webp",
			".html" => "text/html; charset=utf-8",
			".htm" => "text/html; charset=utf-8",
			_ => "application/octet-stream"
		};
	}

	// Forcer l'affichage inline (et fournir un filename "sain" pour l'en-tête)
	var safeFilename = Path.GetFileName(path); // garde ceci pour l'en-tête, évite header injection
	response.Headers["Content-Disposition"] = $"inline; filename=\"{safeFilename}\"";

	// Renvoyer le fichier en stream
	var fs = File.OpenRead(path);
	return Results.File(fs, "application/octet-stream");
});

app.MapGet("/list", () =>
{
	var files = Directory.GetFiles(uploadsDir, "*", SearchOption.TopDirectoryOnly)
						 .Select(p => Path.GetFileName(p))
						 .ToArray();
	return Results.Json(files);
});


Seed.Init(app);

app.Run();

