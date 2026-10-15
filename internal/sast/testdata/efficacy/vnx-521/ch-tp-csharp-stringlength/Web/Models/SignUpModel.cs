using System.ComponentModel.DataAnnotations;

namespace Shop.Web.Models
{
    public class SignUpModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
~>        [StringLength(64, ErrorMessage = "Use {2} to {1} characters.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

~>        [MinLength(4)]
        public string NewPassword { get; set; }
    }
}
