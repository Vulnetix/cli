using System.Diagnostics;
using CliWrap;

namespace Media.Services
{
    public class Converter
    {
        public void Convert(string input, string output)
        {
            var psi = new ProcessStartInfo("bash");
            psi.ArgumentList.Add("/opt/tools/convert.sh");
            psi.ArgumentList.Add(input);
            psi.ArgumentList.Add(output);
            Process.Start(psi)?.WaitForExit();
        }

        public void Listing()
        {
            var psi = new ProcessStartInfo("sh");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("ls -la /var/log/app");
            Process.Start(psi);
        }

        public Task Thumbnail(string file)
        {
            return Cli.Wrap("ffmpeg")
                .WithArguments(new[] { "-i", file, "-vframes", "1", "thumb.png" })
                .ExecuteAsync();
        }
    }
}
