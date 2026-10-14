using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace Api.Services
{
    public class UserService
    {
        private readonly AppDbContext _db;

        public UserService(AppDbContext db) => _db = db;

        public User[] ByName(string name)
        {
~>            return _db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'").ToArray();
        }

        public void DropSessions(string userId)
        {
~>            _db.Database.ExecuteSqlRaw("DELETE FROM Sessions WHERE UserId = " + userId);
        }

        public async Task Rename(string oldName, string newName)
        {
            var sql = $"UPDATE Users SET Name = '{newName}' WHERE Name = '{oldName}'";
~>            await _db.Database.ExecuteSqlRawAsync(sql);
        }

        public Product[] Category(string category)
        {
~>            return _db.Products.FromSql("SELECT * FROM Products WHERE Category = '" + category + "'").ToArray();
        }
    }
}
