using System;
using System.IO;
using System.Web.UI;

public partial class Upload : Page
{
    protected void btnUpload_Click(object sender, EventArgs e)
    {
        if (FileUpload1.HasFile)
        {
            string filename = Path.GetFileName(@@sample:F[i]le[U]pl[o]ad[1][.]F[i]le[N]am[e]@@);
~>            FileUpload1.SaveAs(Server.MapPath("~/uploads/") + filename);
        }
    }
}
