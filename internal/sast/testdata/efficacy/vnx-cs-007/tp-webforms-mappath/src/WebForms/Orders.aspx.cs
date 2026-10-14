using System;
using System.IO;
using System.Web.UI;

namespace WebForms
{
    public partial class Orders : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string targetImage = Request["image"];
            if (targetImage != null)
            {
~>                FileInfo fi = new FileInfo(Server.MapPath(targetImage));
                Response.TransmitFile(fi.FullName);
            }
        }

        protected void Download_Click(object sender, EventArgs e)
        {
~>            Response.WriteFile(MapPath("~/Downloads/" + Request.QueryString["filename"]));
        }

        protected void Open_Click(object sender, EventArgs e)
        {
            var doc = txtDocument.Text;
~>            using (var reader = new StreamReader(Server.MapPath("~/docs/") + doc))
            {
                litBody.Text = reader.ReadToEnd();
            }
        }
    }
}
