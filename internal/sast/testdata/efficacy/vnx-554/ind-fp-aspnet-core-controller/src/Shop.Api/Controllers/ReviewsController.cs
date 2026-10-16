using Ganss.Xss;
using Microsoft.AspNetCore.Mvc;

namespace Shop.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ReviewsController : ControllerBase
{
    private readonly HtmlSanitizer _sanitizer = new();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Post([FromBody] ReviewDto dto)
    {
        var clean = _sanitizer.Sanitize(dto.Body);
        return Ok(new { body = clean });
    }
}

public record ReviewDto(string Body);
