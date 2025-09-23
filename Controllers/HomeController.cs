using dvna.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;

namespace DVNA.Controllers
{
	public class HomeController : Controller
	{
		public IActionResult Index()
		{
			return View();
		}

		[Route("Xss")]
		public IActionResult Xss()
		{
			return View();
		}

		[Route("FileUpload")]
		public IActionResult FileUpload()
		{
			return View();
		}

		[HttpGet]
		public IActionResult Injectcommande()
		{
			return View("Injectcommande");
		}

		[HttpPost]
		public IActionResult Injectcommande(string host)
		{
			if (string.IsNullOrWhiteSpace(host))
			{
				ViewBag.Output = "Veuillez entrer un hôte.";
				return View("Injectcommande");
			}

			// ⚠️ Vulnérable à l'injection de commande – pour démonstration uniquement
			var psi = new ProcessStartInfo
			{
				FileName = "/bin/sh",
				Arguments = $"-c \"ping -c 1 {host}\"",
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			};

			string result;
			try
			{
				using var proc = Process.Start(psi)!;
				result = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
				proc.WaitForExit();
			}
			catch (Exception ex)
			{
				result = "Erreur lors de l'exécution : " + ex.Message;
			}

			ViewBag.Output = result;
			return View("Injectcommande");
		}

		private readonly AppDbContext _db;

		public HomeController(AppDbContext db)
		{
			_db = db;
		}

		[HttpGet]
		public IActionResult SqlInjection()
		{
			return View();
		}

		[HttpGet]
		public IActionResult Auth()
		{
			return View();
		}

		[HttpGet]
		public IActionResult LoginSecure()
		{
			return View();
		}

		[HttpPost]
		public IActionResult SqlInjection(string username, string password)
		{
			if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
			{
				ViewBag.Message = "Entrez utilisateur et mot de passe.";
				return View();
			}

            var user = _db.Users
                .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'")
                .AsEnumerable()   // force exécution côté client après la raw query
                .FirstOrDefault();

			if (user != null)
            {
                ViewBag.Message = $"Connexion réussie — Bienvenue {user.Username} !";
            }
            else
            {
                ViewBag.Message = "Échec de la connexion.";
            }

			// Pour debug : afficher la requête construite (optionnel)
			ViewBag.Query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";
			return View();
		}

		// Version sécurisée d'exemple (LINQ)
		[HttpPost]
		public IActionResult LoginSecure(string username, string password)
		{
			if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
			{
				ViewBag.SecureMessage = "Entrez utilisateur et mot de passe.";
				return View("SqlInjection");
			}

			var user = _db.Users
				.FirstOrDefault(u => u.Username == username && u.Password == password);

			ViewBag.SecureMessage = user != null ? $"connexion sécurisé OK: {user.Username}" : "Utilisation de LINQ pour sécurisé l'application. .FirstOrDefault(u => u.Username == username && u.Password == password);";
			return View("SqlInjection");
		}
	}
}
