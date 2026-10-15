using Microsoft.EntityFrameworkCore;

namespace Sales.Data
{
    public class RegionStats
    {
        private readonly SalesContext _db;

        public RegionStats(SalesContext db) { _db = db; }

        public async Task<List<int>> Count(string region)
        {
            return await _db.Database
~>                .SqlQueryRaw<int>(
                    $"SELECT COUNT(*) AS Value FROM Orders WHERE Region = '{region}'")
                .ToListAsync();
        }

        public Task<int> Purge(string table)
        {
~>            return _db.Database.ExecuteSqlRawAsync("TRUNCATE TABLE " + table);
        }
    }
}
