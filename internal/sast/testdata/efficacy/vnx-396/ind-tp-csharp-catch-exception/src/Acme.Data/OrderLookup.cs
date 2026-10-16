using System;
using System.Data.SqlClient;

namespace Acme.Data
{
    public class OrderLookup
    {
        private readonly string _connString;

        public OrderLookup(string connString)
        {
            _connString = connString;
        }

        public Order Find(int id)
        {
            try
            {
                using var conn = new SqlConnection(_connString);
                conn.Open();
                return OrderMapper.Read(conn, id);
            }
~>            catch (Exception)
            {
                return null;
            }
        }

        public bool TryCancel(int id)
        {
            try
            {
                OrderMapper.Cancel(_connString, id);
                return true;
            }
~>            catch (Exception ex)
            {
                return false;
            }
        }
    }
}
