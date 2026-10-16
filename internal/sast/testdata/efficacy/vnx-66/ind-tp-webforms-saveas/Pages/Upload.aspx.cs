using System;
using System.IO;
using System.Web.UI;

namespace Acme.Portal.Pages
{
    public partial class Upload : Page
    {
        protected void btnUpload_Click(object sender, EventArgs e)
        {
            if (!FileUpload1.HasFile)
            {
                return;
            }
            string filename = Path.GetFileName(FileUpload1.FileName);
~>            FileUpload1.SaveAs(Server.MapPath("~/uploads/") + filename);
            lblStatus.Text = "Uploaded";
        }
    }
}
