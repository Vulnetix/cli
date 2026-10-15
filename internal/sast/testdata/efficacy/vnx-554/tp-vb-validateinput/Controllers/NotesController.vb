Imports System.Web.Mvc

Public Class NotesController
    Inherits Controller

    <HttpPost>
~>    <ValidateInput(False)>
    Function Save(text As String) As ActionResult
        Return View()
    End Function
End Class
