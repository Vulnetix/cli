using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Extensions.Options;

namespace Ops
{
    public class BackupJob
    {
        private readonly BackupOptions _options;

        public BackupJob(IOptions<BackupOptions> options) => _options = options.Value;

        public void Run()
        {
            var file = Path.Combine(_options.Directory, $"db-{DateTime.UtcNow:yyyyMMddHHmm}.dump");
            var psi = new ProcessStartInfo
            {
                FileName = "pg_dump",
                Arguments = $"--format=custom --file={file} {_options.Database}",
                UseShellExecute = false,
            };
            using var proc = Process.Start(psi);
            proc.WaitForExit();
        }
    }
}
