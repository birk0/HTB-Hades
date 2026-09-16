using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace HadesWeb.Models
{
    public class AccountFormModel
    {
        [Display(Name = "Change profile picture")]
        public HttpPostedFileBase ProfilePicture { get; set; }

        [Required(ErrorMessage = "First name is required")]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Last name is required")]
        [Display(Name = "Last Name")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "Display name is required")]
        [Display(Name = "Display Name")]
        public string DisplayName { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [Display(Name = "Email Address")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [Display(Name = "Current Password")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required(ErrorMessage = "Field cannot be empty")]
        [Display(Name = "New Password")]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&#]{7,}$", ErrorMessage = "Must be at least 7 characters long and include at an uppercase letter and number.")
        ]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "Field cannot be empty")]
        [Display(Name = "Confirm Password")]
        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "Password doesn't match")]
        public string ConfirmPassword { get; set; }
    }

    public class UploadFormModel
    {
        [Required(ErrorMessage = "Provide your name" )]
        [Display(Name = "First Name" )]
        public string Name { get; set; }

        [Required(ErrorMessage = "Enter an email address")]
        [EmailAddress(ErrorMessage = "Enter a valid email address")]
        [Display(Name = "Email Address")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Provide a description")]
        [Display(Name = "Report Description")]
        public string Description { get; set; }

        [DataType(DataType.Upload)]
        [Display(Name = "File Upload")]
        public HttpPostedFileBase UploadedFile { get; set; }
    }

    public class SecurityModel
    {

    }

    public class Emails
    {
        public string Roles { get; set; }
        public string Title { get; set; }
        public string Date { get; set; }
        public string Text { get; set; }
    }
}