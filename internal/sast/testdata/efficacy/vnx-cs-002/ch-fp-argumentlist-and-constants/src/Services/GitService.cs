using System.Diagnostics;

namespace Ops.Services;

public class GitService
{
    public string Log(string branch)
    {
        var psi = new ProcessStartInfo("git") { RedirectStandardOutput = true };
        psi.ArgumentList.Add("log");
        psi.ArgumentList.Add("--oneline");
        psi.ArgumentList.Add(branch);
        using var p = Process.Start(psi)!;
        return p.StandardOutput.ReadToEnd();
    }

    public void OpenDocs() => Process.Start(new ProcessStartInfo("https://docs.example.com") { UseShellExecute = true });

    public void Status() => Process.Start("git", "status --porcelain");

    public void Build(int jobs) => Process.Start("dotnet", "build -m:" + jobs.ToString());
}
