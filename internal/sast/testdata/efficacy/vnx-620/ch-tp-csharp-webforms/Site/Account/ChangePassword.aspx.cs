using System;
using System.Web.UI;

namespace Shop.Site.Account
{
    public partial class ChangePassword : Page
    {
        private readonly IAccountStore store = AccountStore.Current;

        protected void SaveButton_Click(object sender, EventArgs e)
        {
            if (txtNew.Text == txtConfirm.Text)
            {
                int accountId = int.Parse(Request.Cookies["accountId"].Value);
~>                lblResult.Text = store.UpdateAccountPassword(accountId, txtNew.Text);
            }
        }
    }
}
