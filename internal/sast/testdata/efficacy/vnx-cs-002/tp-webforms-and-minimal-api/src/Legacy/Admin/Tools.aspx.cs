using System;
using System.Diagnostics;
using System.Web.UI;

namespace Legacy.Admin
{
    public partial class Tools : Page
    {
        protected void btnOpen_Click(object sender, EventArgs e)
        {
            string file = Request.QueryString["file"];
~>            Process.Start(file);
        }

        protected void btnRun_Click(object sender, EventArgs e)
        {
            var info = new ProcessStartInfo();
~>            info.FileName = txtProgram.Text;
            info.UseShellExecute = false;
            Process.Start(info);
        }
    }
}
