using System;
using System.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace Diagnostics
{
    public class QueryTracer
    {
        private readonly ILogger<QueryTracer> _logger;
        private readonly JobRunner _jobs;

        public QueryTracer(ILogger<QueryTracer> logger, JobRunner jobs)
        {
            _logger = logger;
            _jobs = jobs;
        }

        public void Trace(SqlCommand cmd, string user)
        {
            // Never do this: var bad = new SqlCommand("SELECT * FROM Users WHERE Name = '" + user + "'", conn);
            /* cmd.CommandText = "DELETE FROM Users WHERE Id = " + user; */
            _logger.LogInformation("CommandText = " + cmd.CommandText + " for " + user);
            Console.WriteLine("new SqlCommand(\"SELECT\" + x) is unsafe, user " + user);
            if (cmd.CommandText == "SELECT 1" + Environment.NewLine)
            {
                _logger.LogDebug("health probe");
            }
            _jobs.Execute("cleanup-" + user);
            var label = new CommandLabel("Run " + user);
        }
    }
}
