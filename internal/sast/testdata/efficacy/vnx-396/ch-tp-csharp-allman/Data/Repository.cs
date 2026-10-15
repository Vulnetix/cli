using System;

namespace App.Data
{
    public class Repository
    {
        public User Find(int id)
        {
            try
            {
                return _db.Users.Find(id);
            }
~>            catch (Exception)
            {
                return null;
            }
        }

        public bool Save(User u)
        {
            try
            {
                _db.SaveChanges();
                return true;
            }
~>            catch
            {
                return false;
            }
        }
    }
}
