using System;
using System.Diagnostics;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace Web.Export
{
    public class ExportService
    {
        private readonly ILogger<ExportService> _logger;

        public ExportService(ILogger<ExportService> logger) => _logger = logger;

        public ContentDispositionHeaderValue Disposition(string name)
        {
            var cd = new ContentDispositionHeaderValue("attachment") { FileName = "report-" + name + ".pdf" };
            return cd;
        }

        public void Save(SaveDialog dialog, DateTime date, string input)
        {
            dialog.FileName = "export_" + date.ToString("yyyyMMdd") + ".csv";
            // Process.Start("cmd.exe", "/c " + input);
            _logger.LogWarning("refusing Process.Start(\"cmd.exe\", \"/c " + input + "\")");
            var psi = new ProcessStartInfo("dotnet", "--info");
            Process.Start(psi);
        }
    }
}
