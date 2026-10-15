using System.ComponentModel.DataAnnotations;

namespace Shop.Web.Models
{
    public class VerifyModel
    {
        [Required]
        [StringLength(7, ErrorMessage = "Enter the {2} digit code.", MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = "Verification Code")]
        public string Code { get; set; }

        [StringLength(128, MinimumLength = 12)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [MinLength(3)]
        public string DisplayName { get; set; }
    }
}
