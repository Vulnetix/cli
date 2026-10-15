using System;
using System.Web.UI;

namespace Site
{
    public partial class Comment : Page
    {
        protected void Save_Click(object sender, EventArgs e)
        {
            Response.Write(Body.Text);
        }
    }
}
