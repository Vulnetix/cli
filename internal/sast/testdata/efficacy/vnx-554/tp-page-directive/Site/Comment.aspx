~><%@ Page Language="C#" AutoEventWireup="true" ValidateRequest="false" CodeBehind="Comment.aspx.cs" Inherits="Site.Comment" %>
<!DOCTYPE html>
<html>
<body>
  <form runat="server">
    <asp:TextBox ID="Body" runat="server" TextMode="MultiLine" />
    <asp:Button ID="Save" runat="server" Text="Save" OnClick="Save_Click" />
  </form>
</body>
</html>
