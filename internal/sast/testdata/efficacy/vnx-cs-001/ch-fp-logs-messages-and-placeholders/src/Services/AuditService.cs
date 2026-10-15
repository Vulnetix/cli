using Microsoft.Extensions.Logging;

namespace Shop.Services;

public class AuditService
{
    private readonly ILogger<AuditService> _log;

    public AuditService(ILogger<AuditService> log) => _log = log;

    public void Record(string user, string table)
    {
        _log.LogInformation($"User {user} ran SELECT on {table}");
        var message = "Query failed for " + user + ": SqlCommand timed out";
        throw new InvalidOperationException($"Could not ExecuteSqlRaw for {table}: {message}");
    }

    // Never write: new SqlCommand("SELECT * FROM t WHERE x = '" + input + "'")
    public string Help() => "Use FromSqlInterpolated($\"... {value}\") instead of string concatenation";
}
