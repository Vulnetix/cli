using System.Diagnostics;

namespace Tools.Git
{
    public class GitRunner
    {
        private const string ShellPath = "/bin/sh";

        public void OpenEditor()
        {
            Process.Start("notepad.exe");
            Process.Start(new ProcessStartInfo("git", "status --porcelain") { UseShellExecute = false });
        }

        public void Checkout(string branch)
        {
            var psi = new ProcessStartInfo { FileName = "git", UseShellExecute = false };
            psi.ArgumentList.Add("checkout");
            psi.ArgumentList.Add(branch);
            Process.Start(psi);
        }

        public void Clone(string repoUrl, string dir)
        {
            Process.Start("git", $"clone --depth 1 {repoUrl} {dir}");
        }

        public void Reveal(string folder)
        {
            Process.Start("explorer.exe", folder);
        }

        public void Fixed()
        {
            Process.Start("cmd.exe", "/c echo ready");
            Process.Start(ShellPath, "-c \"" + "uptime" + "\"");
        }
    }
}
