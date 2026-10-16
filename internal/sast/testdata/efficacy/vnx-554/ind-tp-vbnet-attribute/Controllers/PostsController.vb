Imports System.Web.Mvc

Public Class PostsController
    Inherits Controller

    <HttpPost>
~>    <ValidateInput(False)>
    Function Create(title As String, body As String) As ActionResult
        Return RedirectToAction("Index")
    End Function
End Class
