// ================================
// Projet : DVNA (Damn Vulnerable .NET App)
// Auteur : Lamri [aka ingenius]
// Date : 2025
// Description : Application web ASP.NET Core volontairement vulnérable pour l’apprentissage de la sécurité
// ================================
// ajout du plugin sqlite dotnet add package Microsoft.EntityFrameworkCore.Sqlite && dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer avant dotnet run

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using dvna.Data;
using dvna.Models;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;





WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

var jwtKey = "super-secret-key-12345gsecret-key-12345jnhhyyfdTYYU5"; // TODO: remplacer en production
var issuer = "MyAPI";
var audience = "MyAPIUsers";

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = issuer,
        ValidAudience = audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
});

builder.Services.AddAuthorization();

builder.Services.AddControllersWithViews();

// ➕ Ajout de SQLite
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite("Data Source=lab.db"));

var uploadsDir = Path.Combine(Directory.GetCurrentDirectory(), "uploads");
Directory.CreateDirectory(uploadsDir);

// Ajouter les services MVC
builder.Services.AddControllersWithViews();

WebApplication app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

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

app.MapControllerRoute(
    name: "Path",
    pattern: "Path",
    defaults: new { controller = "Home", action = "pathtrersal" });

app.MapGet("/sys/{*path}", async (HttpContext context, string? path) =>
{
    var basePath = Path.Combine(Directory.GetCurrentDirectory(), "/");
    var fullPath = string.IsNullOrEmpty(path)
        ? basePath
        : Path.Combine(basePath, path);



    // Si dossier → liste son contenu
    if (Directory.Exists(fullPath))
    {
        IEnumerable<string?> dossiers = Directory.GetDirectories(fullPath)
            .Select(Path.GetFileName);
        IEnumerable<string?> fichiers = Directory.GetFiles(fullPath)
            .Select(Path.GetFileName);

        await context.Response.WriteAsJsonAsync(new { Dossiers = dossiers, Fichiers = fichiers });
        return;
    }

    // Si fichier → le renvoyer
    if (System.IO.File.Exists(fullPath))
    {
        var contentType = "application/octet-stream";
        await context.Response.SendFileAsync(fullPath, context.RequestAborted);
        return;
    }

    context.Response.StatusCode = 404;
    await context.Response.WriteAsync("Chemin introuvable.");
});


app.MapPost("/upload", async (HttpRequest req) =>
{
    if (!req.HasFormContentType)
        return Results.BadRequest("form-data attendu.");

    IFormCollection form = await req.ReadFormAsync();
    IFormFile? file = form.Files["file"];
    if (file == null)
        return Results.BadRequest("fichier manquant (champ 'file').");

    var providedName = form["filename"].FirstOrDefault() ?? file.FileName ?? "unnamed";

    // === VULN : on combine directement sans normalisation (intentionnel)
    var destPath = Path.Combine(uploadsDir, providedName);

    // Create directory if user supplied subfolder in name (still vuln: allows ../ if providedName has traversal sequences)
    Directory.CreateDirectory(Path.GetDirectoryName(destPath) ?? uploadsDir);

    await using (FileStream fs = File.Create(destPath))
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

    var provider = new FileExtensionContentTypeProvider();
    if (!provider.TryGetContentType(path, out var contentType))
    {
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
    FileStream fs = File.OpenRead(path);
    return Results.File(fs, "application/octet-stream");
});

app.MapGet("/list", () =>
{
    var files = Directory.GetFiles(uploadsDir, "*", SearchOption.TopDirectoryOnly)
                         .Select(p => Path.GetFileName(p))
                         .ToArray();
    return Results.Json(files);
});

app.Use(async (context, next) =>
{
    var token = context.Request.Cookies["jwt"];
    if (!string.IsNullOrEmpty(token))
    {
        context.Request.Headers["Authorization"] = $"Bearer {token}";
    }

    await next();
});

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/login", async (UserLogin user, AppDbContext db, HttpResponse response) =>
{
    User? dbUser = await db.Users.SingleOrDefaultAsync(u => u.Username == user.Username);

    if (dbUser is null || dbUser.Password != user.Password)
    {
        return Results.Unauthorized();
    }

    Claim[] claims = new[]
    {
        new Claim(ClaimTypes.Name, dbUser.Username),
        new Claim(ClaimTypes.Role, "User")
    };

    // 2. Clé de signature
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    // 3. Créer le token JWT
    var token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(30),
        signingCredentials: creds);

    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

    response.Cookies.Append("jwt", tokenString, new CookieOptions
    {
        HttpOnly = true,
        Secure = false,
        SameSite = SameSiteMode.Strict,
        Expires = DateTimeOffset.UtcNow.AddMinutes(30)
    });

    return Results.Ok(new { token = tokenString });
});


app.MapGet("/api", async (AppDbContext db) =>
{
    return "Se connecter via curl (POST /api/login) avec l’utilisateur user, puis appeler GET /api/list pour récupérer la liste des utilisateurs et trouver le mot de passe de l’admin.";
});

app.MapGet("/api/list", async (AppDbContext db) =>
{
    return await db.Users.ToListAsync();
})
.RequireAuthorization();

app.MapGet("/api/{id}", async (int id, AppDbContext db) =>
{
    User? person = await db.Users.FindAsync(id);
    return person is not null ? Results.Ok(person) : Results.NotFound();
})
.RequireAuthorization();


Seed.Init(app);

app.UseDeveloperExceptionPage();


app.Run();

// PS Je sais que je doit mettre les actions dans le controller, je referait un refactorine dès que possible..
