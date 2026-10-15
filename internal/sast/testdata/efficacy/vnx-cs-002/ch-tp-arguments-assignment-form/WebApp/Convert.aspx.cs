using System;
using System.Diagnostics;
using System.Web.UI;

public partial class ConvertPage : Page
{
    protected void Convert_Click(object sender, EventArgs e)
    {
        var info = new ProcessStartInfo();
        info.FileName = "powershell.exe";
~>        info.Arguments = $"-Command \"ConvertTo-Pdf {Request.Form["document"]}\"";
        info.UseShellExecute = false;
        Process.Start(info);
    }
}
