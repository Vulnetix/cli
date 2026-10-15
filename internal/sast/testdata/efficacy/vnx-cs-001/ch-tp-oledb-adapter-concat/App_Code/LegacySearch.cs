using System.Data;
using System.Data.OleDb;
using System.Web;

public class LegacySearch
{
    public DataTable Search(HttpRequest request, OleDbConnection conn)
    {
        string term = request.QueryString["q"];
~>        var adapter = new OleDbDataAdapter("SELECT * FROM Products WHERE Name LIKE '%" + term + "%'", conn);
        var table = new DataTable();
        adapter.Fill(table);
        return table;
    }

    public void Archive(OleDbConnection conn, string year)
    {
        OleDbCommand cmd = conn.CreateCommand();
~>        cmd.CommandText = $"INSERT INTO Archive SELECT * FROM Sales WHERE Year = {year}";
        cmd.ExecuteNonQuery();
    }
}
