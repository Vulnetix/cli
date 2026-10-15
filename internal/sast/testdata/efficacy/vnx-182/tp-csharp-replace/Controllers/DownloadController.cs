using System.IO;
using Microsoft.AspNetCore.Mvc;

public class DownloadController : Controller
{
    public IActionResult Get(string file)
    {
~>        var name = file.Replace("..\\", "");
        return PhysicalFile(Path.Combine("C:\\data", name), "application/octet-stream");
    }
}
