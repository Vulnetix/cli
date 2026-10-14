using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;

namespace Api.Services
{
    public class SafeUserService
    {
        private readonly AppDbContext _db;

        public SafeUserService(AppDbContext db) => _db = db;

        public User[] ByName(string name)
        {
            return _db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}").ToArray();
        }

        public User[] ByEmail(string email)
        {
            return _db.Users.FromSql($"SELECT * FROM Users WHERE Email = {email}").ToArray();
        }

        public void Drop(string userId)
        {
            _db.Database.ExecuteSqlInterpolated($"DELETE FROM Sessions WHERE UserId = {userId}");
            _db.Database.ExecuteSqlRaw("DELETE FROM Sessions WHERE UserId = {0}", userId);
        }

        public int[] Ids(string tenant)
        {
            FormattableString q = $"SELECT Id FROM Users WHERE Tenant = {tenant}";
            return _db.Database.SqlQuery<int>(q).ToArray();
        }

        public User[] Active()
        {
            return _db.Users.FromSqlRaw("SELECT * FROM Users WHERE Active = 1").ToArray();
        }
    }
}
