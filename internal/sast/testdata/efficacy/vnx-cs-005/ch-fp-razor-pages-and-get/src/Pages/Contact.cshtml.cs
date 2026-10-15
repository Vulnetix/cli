using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Site.Pages;

public class ContactModel : PageModel
{
    [BindProperty]
    public string Message { get; set; } = "";

    public void OnGet() { }

    public IActionResult OnPost()
    {
        _mail.Send(Message);
        return RedirectToPage("Thanks");
    }
}
