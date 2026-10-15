<%@ Page
    Title="Content editor"
    Language="C#"
    MasterPageFile="~/Site.Master"
    AutoEventWireup="true"
    CodeBehind="Editor.aspx.cs"
    Inherits="Cms.Admin.Editor"
~>    ValidateRequest="false" %>
<asp:Content ID="Body" ContentPlaceHolderID="MainContent" runat="server">
    <asp:TextBox ID="Html" runat="server" TextMode="MultiLine" />
</asp:Content>
