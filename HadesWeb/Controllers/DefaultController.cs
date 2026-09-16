using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using HadesWeb.Models;
using Newtonsoft.Json;

namespace HadesWeb.Controllers
{
    [Authorize]
    public class DefaultController : Controller
    {
        //GET: Home page
        [AllowAnonymous]
        public ActionResult Index()
        {
            return View();
        }

        // GET: /Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        // POST: /Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid login attempt");
                ModelState.Remove("Email");
                model.Email = string.Empty;
                return View();
            }

            var Users = GetUsers();
            var user = Users.FirstOrDefault(u => u.Email.Equals(model.Email));

            if (user != null && PasswordManager.ValidatePassword(model.Password, user.Password))
            {
                var authTicket = new FormsAuthenticationTicket(1, user.Email, DateTime.Now, DateTime.Now.AddDays(7), model.RememberMe, user.Role, FormsAuthentication.FormsCookiePath);

                string Ticket = FormsAuthentication.Encrypt(authTicket);
                var Cookie = new HttpCookie(FormsAuthentication.FormsCookieName, Ticket);

                if (model.RememberMe)
                {
                    Cookie.Expires = authTicket.Expiration;
                }

                Response.Cookies.Add(Cookie);

                return RedirectToLocal(returnUrl);
            }

            ModelState.AddModelError("", "Invalid login attempt");
            ModelState.Remove("Email");
            model.Email = string.Empty;
            return View();

        }

        //Post: /Logout
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "Default");
        }


        private List<UsersList> GetUsers()
        {
            var Path = Server.MapPath("~/App_Data/Users.json");
            var Data = System.IO.File.ReadAllText(Path);
            return JsonConvert.DeserializeObject<List<UsersList>>(Data);
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }
    }
}