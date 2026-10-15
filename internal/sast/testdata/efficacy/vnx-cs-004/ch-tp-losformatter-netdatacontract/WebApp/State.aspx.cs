using System;
using System.IO;
using System.Runtime.Serialization;
using System.Web.UI;

public partial class StatePage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        var lf = new LosFormatter();
~>        object state = lf.Deserialize(Request.Form["state"]);

        var ndcs = new NetDataContractSerializer();
~>        object prefs = ndcs.ReadObject(Request.InputStream);
    }
}
