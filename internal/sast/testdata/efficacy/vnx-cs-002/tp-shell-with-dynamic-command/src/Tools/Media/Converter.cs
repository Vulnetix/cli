using System.Diagnostics;

namespace Tools.Media
{
    public class Converter
    {
        public void Convert(string inputFile)
        {
~>            Process.Start("cmd.exe", "/c magick convert " + inputFile + " out.png");
        }

        public string Ping(string host)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
~>                Arguments = $"-c \"ping -c 1 {host}\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            using var p = Process.Start(psi);
            return p.StandardOutput.ReadToEnd();
        }

        public void Pack(string archive, string folder)
        {
            var startInfo = new ProcessStartInfo();
            startInfo.FileName = "sh";
~>            startInfo.Arguments = string.Format("-c \"tar -czf {0} {1}\"", archive, folder);
            Process.Start(startInfo);
        }

        public void Remove(string path)
        {
~>            System.Diagnostics.Process.Start("powershell.exe",
                $"-NoProfile -Command Remove-Item -Recurse {path}");
        }

        public void Run(string script)
        {
            string commandLine = "/c " + script;
~>            var psi = new ProcessStartInfo("cmd", commandLine);
            Process.Start(psi);
        }
    }
}
