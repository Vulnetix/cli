using System;
using System.Net;
using System.Web.UI;

namespace WebForms
{
    public partial class Feed : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string feed = Request.QueryString["feed"];
            using (var wc = new WebClient())
            {
~>                litFeed.Text = wc.DownloadString(feed);
            }
        }

        protected void Check_Click(object sender, EventArgs e)
        {
~>            var req = (HttpWebRequest)WebRequest.Create(Request["u"]);
            using var resp = req.GetResponse();
        }

        protected void Fetch_Click(object sender, EventArgs e)
        {
            var web = new WebClient();
~>            web.DownloadFile(new Uri(txtImageUrl.Text), Server.MapPath("~/cache/img.png"));
~>            using var stream = new WebClient().OpenRead(txtFeedUrl.Text);
        }
    }
}
