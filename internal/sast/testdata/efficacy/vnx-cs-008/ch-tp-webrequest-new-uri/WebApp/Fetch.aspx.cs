using System;
using System.IO;
using System.Net;
using System.Web.UI;

public partial class FetchPage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
~>        var req = (HttpWebRequest)WebRequest.Create(new Uri(Request.QueryString["u"]));
        using (var resp = req.GetResponse())
        using (var reader = new StreamReader(resp.GetResponseStream()))
        {
            Response.Write(reader.ReadToEnd());
        }
    }
}
