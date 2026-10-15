using System;
using System.Net;
using System.Web.UI;

public partial class MirrorPage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        using (var wc = new WebClient())
        {
~>            string body = wc.DownloadString(Request["url"]);
            Response.Write(body);
        }
    }
}
