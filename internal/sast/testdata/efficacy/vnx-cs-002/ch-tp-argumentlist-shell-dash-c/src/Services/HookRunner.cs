using System.Diagnostics;

namespace Deploy.Services
{
    public class HookRunner
    {
        public string Run(string hookCommand)
        {
            var psi = new ProcessStartInfo("/bin/bash")
            {
                RedirectStandardOutput = true,
            };
            psi.ArgumentList.Add("-c");
~>            psi.ArgumentList.Add(hookCommand);
            using var proc = Process.Start(psi);
            return proc.StandardOutput.ReadToEnd();
        }

        public void RunWindows(string target)
        {
            var info = new ProcessStartInfo { FileName = "cmd.exe" };
            info.ArgumentList.Add("/c");
~>            info.ArgumentList.Add("ping " + target);
            Process.Start(info);
        }
    }
}
