using System.ComponentModel.DataAnnotations;

namespace Web.Models
{
    public class RegisterModel
    {
        public string Email { get; set; }

        public string Password { get; set; }

        public bool IsValid()
        {
~>            return Password != null && Password.Length >= 4;
        }
    }
}
