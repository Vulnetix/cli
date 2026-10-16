using System.Diagnostics;

namespace BuildAgent
{
    public class Toolchain
    {
        public string DotnetInfo()
        {
            var psi = new ProcessStartInfo("dotnet", "--info")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            using var p = Process.Start(psi);
            return p.StandardOutput.ReadToEnd();
        }

        public void Checkout(string branch, string workDir)
        {
            var psi = new ProcessStartInfo { FileName = "git", WorkingDirectory = workDir, UseShellExecute = false };
            psi.ArgumentList.Add("checkout");
            psi.ArgumentList.Add("--");
            psi.ArgumentList.Add(branch);
            Process.Start(psi)?.WaitForExit();
        }

        public void CleanTemp()
        {
            Process.Start("cmd.exe", "/c del /q %TEMP%\\build-*.log");
        }
    }
}
