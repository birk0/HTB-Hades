using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using HadesWeb.Models;
using Microsoft.AspNet.Identity;
using Newtonsoft.Json;

namespace HadesWeb.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        // GET: Home
        public ActionResult Index()
        {
            return View();
        }
        public ActionResult Account()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Account(AccountFormModel model)
        {
            if (ModelState.IsValid)
            {
                ModelState.AddModelError("", "Confirm your email address before performing this action");
                return View(model);
            }

            return View(model);
        }

        public ActionResult Mail()
        {
            string[] roles = ((FormsIdentity)User.Identity).Ticket.UserData.Split(',');
            var Emails = GetEmails(roles);

            return View(Emails);
        }
        public ActionResult Downloads()
        {
            return View();
        }
        public ActionResult Security()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Security(SecurityModel model)
        {
            ViewBag.Message = "You must confirm your email before performing this action.";
            return View(model);
        }

        public ActionResult Forms()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Forms(UploadFormModel model)
        {
            if (ModelState.IsValid)
            {
                if (model.UploadedFile != null && model.UploadedFile.ContentLength > 0)
                {
                    if (User.IsInRole("Administrators"))
                    {
                        int FileSize = (1 * 1024 * 1024);
                        if (model.UploadedFile.ContentLength < FileSize)
                        {
                            string[] AllowedExtensions = { ".docx",".odt",".pdf" };
                            string extension = Path.GetExtension(model.UploadedFile.FileName).ToLower();
                            
                            if (AllowedExtensions.Contains(extension))
                            {
                                try
                                {
                                    string fileName = $"{Guid.NewGuid()}{extension}";
                                    string path = Path.Combine("C:\\Users\\user\\Desktop", Path.GetFileName(fileName));

                                    model.UploadedFile.SaveAs(path);
                                    ViewBag.Success = "Thank you for your report!";
                                }
                                catch (Exception) { }
                            }
                            else { ViewBag.Message = "File type is not supported."; }
                        } 
                        else { ViewBag.Message = "File too large."; }
                    }
                    else { ViewBag.Message = "File Upload not permitted."; }
                }
                else { ViewBag.Success = "Thank you for your report!"; }
            }
            return View(model);
        }

        public ActionResult Download(string fileName)
        {
            try
            {
                string filePath = Server.MapPath($"~/App_Data/Downloads/{fileName}");
                string fileType = MimeMapping.GetMimeMapping(fileName);

                return File(filePath, fileType, fileName);
            }

            catch (Exception)
            {
                return new HttpStatusCodeResult(System.Net.HttpStatusCode.InternalServerError);
            }
        }

        //grab serialised email objects matching login address
        private List<Emails> GetEmails(string[] roles)
        {
            var Path = Server.MapPath("~/App_Data/emails.json");
            var Data = System.IO.File.ReadAllText(Path);
            var Objects = JsonConvert.DeserializeObject<List<Emails>>(Data);

            return Objects.Where(e => roles.Contains(e.Roles)).ToList();
        }

        
    }
}