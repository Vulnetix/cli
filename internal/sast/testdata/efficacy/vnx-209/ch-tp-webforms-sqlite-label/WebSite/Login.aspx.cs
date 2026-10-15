using System;
using System.Data.SQLite;

public partial class Login : System.Web.UI.Page
{
    protected void btnLogin_Click(object sender, EventArgs e)
    {
        try
        {
            using (var cmd = new SQLiteCommand("SELECT 1 FROM users WHERE name = @n", Db.Connection))
            {
                cmd.Parameters.AddWithValue("@n", txtUser.Text);
                cmd.ExecuteScalar();
            }
        }
        catch (SQLiteException ex)
        {
~>            lblError.Text = "Login failed: " + ex.Message;
        }
        catch (Exception)
        {
            lblError.Text = "Login failed.";
        }
    }
}
