using System;
using System.IO;
using System.Web.UI;

public partial class RemovePage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
~>        File.Delete(Server.MapPath("~/uploads/" + Request.QueryString["f"]));
    }
}
