using Microsoft.AspNetCore.Mvc;

namespace Tranactify_UI.Controllers
{
    public class IdentityController : Controller
    {
        public IActionResult Login()
        {
            return View();
        }
        public IActionResult Register()
        {
            return View();
        }
    }
}
