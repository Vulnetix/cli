using CliWrap;
using CliWrap.Buffered;

namespace Backup.Jobs
{
    public class ArchiveJob
    {
        public async Task<string> Pack(string folder)
        {
            var result = await Cli.Wrap("sh")
~>                .WithArguments($"-c \"tar czf /backups/out.tgz {folder}\"")
                .ExecuteBufferedAsync();
            return result.StandardOutput;
        }
    }
}
