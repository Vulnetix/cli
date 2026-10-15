using Dapper;
using Npgsql;

namespace Accounts.Repositories;

public sealed class UserRepository
{
    private readonly NpgsqlConnection _conn;

    public UserRepository(NpgsqlConnection conn) => _conn = conn;

    public Task<User?> FindByEmail(string email) =>
~>        _conn.QueryFirstOrDefaultAsync<User>($@"SELECT id, email
            FROM users
            WHERE email = '{email}'");

    public async Task<int> Rename(int id, string name)
    {
~>        await using var cmd = new NpgsqlCommand(
            "UPDATE users SET name = '" + name + "' WHERE id = " + id, _conn);
        return await cmd.ExecuteNonQueryAsync();
    }
}
