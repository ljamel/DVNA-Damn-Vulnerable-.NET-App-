using Microsoft.AspNetCore.Mvc;

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
    }
}
