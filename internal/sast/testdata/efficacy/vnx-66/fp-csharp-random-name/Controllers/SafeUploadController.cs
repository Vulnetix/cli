using System;
using System.IO;
using Microsoft.AspNetCore.Http;

public class SafeUploadController
{
    public string Upload(IFormFile file, Document doc)
    {
        var path = Path.Combine("/srv/uploads", Path.GetRandomFileName());
        var other = Path.Combine("/srv/uploads", Guid.NewGuid() + Path.GetExtension(file.FileName));
        doc.OriginalName = file.FileName;
        return path + other;
    }
}
