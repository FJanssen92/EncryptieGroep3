using Microsoft.AspNetCore.Mvc;

namespace EncryptieGroep3.Controllers
{
    public class SecurityController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [ActionName("Part 1")]
        public IActionResult Part1()
        {
            return View("Part1");
        }

        [ActionName("Part 2")]
        public IActionResult Part2()
        {
            return View("Part2");
        }

        [ActionName("Part 3")]
        public IActionResult Part3()
        {
            return View("Part3");
        }

        [ActionName("Part 4")]
        public IActionResult Part4()
        {
            return View("Part4");
        }
    }
}
