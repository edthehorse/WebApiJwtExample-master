using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApiJwtExample
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize] 
        public IActionResult GetUserDetails(){ // This powerful  [Authorize] tag only allows it to be executed if authorized!

            return new ObjectResult(new { Username = User.Identity.Name  });  // Sends it back to the form.              
        }
    }
}