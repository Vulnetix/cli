using Npgsql;

namespace Etl
{
    public sealed class Loader
    {
        private readonly string _host;
        private readonly string _db;

        public Loader(string host, string db)
        {
            _host = host;
            _db = db;
        }

        public NpgsqlConnection Connect()
        {
~>            var cs = $"Host={_host};Username=etl;Password=Etl-Load-9;Database={_db}";
            return new NpgsqlConnection(cs);
        }
    }
}
