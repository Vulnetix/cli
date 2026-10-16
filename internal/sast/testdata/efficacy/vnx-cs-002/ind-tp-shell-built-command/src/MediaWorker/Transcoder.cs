using System.Diagnostics;
using System.Threading.Tasks;

namespace MediaWorker
{
    public class Transcoder
    {
        public async Task ToMp4Async(string inputPath, string outputPath, int bitrateKbps)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
~>                Arguments = $"-c \"ffmpeg -y -i '{inputPath}' -b:v {bitrateKbps}k '{outputPath}'\"",
                UseShellExecute = false,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            await proc.WaitForExitAsync();
        }

        public void Thumbnail(string source)
        {
~>            Process.Start("cmd.exe", string.Format("/c magick convert {0} -resize 200x200 thumb.png", source));
        }

        public void RunHook(string hookCommand)
        {
            var psi = new ProcessStartInfo("sh") { UseShellExecute = false };
            psi.ArgumentList.Add("-c");
~>            psi.ArgumentList.Add(hookCommand);
            Process.Start(psi)?.WaitForExit();
        }
    }
}
