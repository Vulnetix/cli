using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Ops.Tools;

public class Launcher
{
    public void OpenFolder(string folderPath)
    {
        Process.Start("explorer.exe", folderPath);
    }

    public void Ping(string host)
    {
        if (!Regex.IsMatch(host, "^[a-zA-Z0-9.-]{1,253}$"))
        {
            throw new ArgumentException("bad host");
        }
        Process.Start("ping", "-c 1 " + host);
    }
}
