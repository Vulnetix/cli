using Microsoft.Data.SqlClient;

namespace Accounts
{
    public sealed class AccountStore
    {
        private readonly SqlConnection _conn;

        public AccountStore(SqlConnection conn) => _conn = conn;

        public bool Login(string user, string hash)
        {
            using var cmd = new SqlCommand("SELECT COUNT(*) FROM Users WHERE Username = @u AND Password = @p", _conn);
            cmd.Parameters.AddWithValue("@u", user);
            cmd.Parameters.AddWithValue("@Password", hash);
            return (int)cmd.ExecuteScalar() == 1;
        }

        public void Change(int id, string name, string hash)
        {
            var sql = "UPDATE Users SET Name = @n, Password = @p WHERE Id = @id";
            var legacy = "update CustomerLogin set password = '" + hash + "' where customerNumber = " + id;
            using var cmd = new SqlCommand(sql + legacy, _conn);
            cmd.ExecuteNonQuery();
        }

        public string Encoded(string pwd)
        {
            string encoded_password = Encode(pwd);
            return "' and password = '" + encoded_password + "';";
        }

        public LoginModel Blank() => new LoginModel { UserName = "", Password = "" };

        public LoginModel Demo(string cs)
        {
            var builder = new SqlConnectionStringBuilder(cs);
            var model = new LoginModel
            {
                UserName = builder.UserID,
                Password = "demo-login-1",
            };
            return model;
        }

        private static string Encode(string s) => s;
    }

    public sealed class LoginModel
    {
        public string UserName { get; set; } = "";
        public string Password { get; set; } = "";
    }
}
