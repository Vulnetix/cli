using System;
using System.IO;
using System.Web.UI;

namespace LegacySite
{
    public partial class Viewer : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string doc = Request.QueryString["doc"];
~>            Response.TransmitFile(Server.MapPath("~/documents/" + doc));
        }

        protected void Save_Click(object sender, EventArgs e)
        {
~>            File.WriteAllText(@"C:\inetpub\notes\" + txtFileName.Text, txtBody.Text);
        }
    }
}
