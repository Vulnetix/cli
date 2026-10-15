using Microsoft.Data.SqlClient;
using NHibernate;

namespace Shop.Data;

public class LegacyQueries
{
    private readonly ISession _session;
    private readonly SqlConnection _conn;

    public LegacyQueries(ISession session, SqlConnection conn)
    {
        _session = session;
        _conn = conn;
    }

    public IList<Product> ByName(string name) =>
~>        _session.CreateSQLQuery("SELECT * FROM Products WHERE Name = '" + name + "'")
            .AddEntity(typeof(Product))
            .List<Product>();

    public IList<Product> ByCategory(string category) =>
~>        _session.CreateQuery($"from Product p where p.Category = '{category}'").List<Product>();

    public SqlCommand Find(string sku)
    {
~>        var cmd = new SqlCommand($"""
            SELECT Id, Name
            FROM Products
            WHERE Sku = '{sku}'
            """, _conn);
        return cmd;
    }
}
