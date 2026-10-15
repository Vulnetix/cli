using System;
using System.Diagnostics;
using System.Web.UI;

public partial class TracePage : Page
{
    protected void Run_Click(object sender, EventArgs e)
    {
        var p = new Process();
        p.StartInfo.FileName = "cmd.exe";
~>        p.StartInfo.Arguments = "/c tracert " + txtHost.Text;
        p.StartInfo.UseShellExecute = false;
        p.Start();
    }
}
