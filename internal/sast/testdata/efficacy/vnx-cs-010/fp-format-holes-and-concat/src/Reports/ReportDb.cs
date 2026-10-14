using System;
using Npgsql;

namespace Reports
{
    public sealed class ReportDb
    {
        private readonly string _server;
        private readonly string _user;
        private readonly string _password;

        public ReportDb(string server, string user, string password)
        {
            _server = server;
            _user = user;
            _password = password;
        }

        public string Formatted() =>
            string.Format("Server={0};Database=Reports;User Id={1};Password={2};", _server, _user, _password);

        public string Interpolated() => $"Host={_server};Username={_user};Password={_password};Database=reports";

        public string Concatenated() => "Server=" + _server + ";User Id=" + _user + ";Password=" + _password + ";";

        public string Empty() => "Server=localhost;Database=Reports;User Id=guest;Password=;";

        public string Spaced() => "Host=localhost;Username=guest;Password= ;Database=reports";

        public string Mysql() => string.Format("SERVER={0};PORT={1};DATABASE={2};UID={3};PWD={4}", _server, 3306, "shop", _user, _password);

        public NpgsqlConnection Open() => new NpgsqlConnection(Interpolated());

        public string Masked(string cs) => cs.Replace("Password=", "Password=***");
    }
}
