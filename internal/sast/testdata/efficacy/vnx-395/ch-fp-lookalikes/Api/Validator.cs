using System;

public class Validator
{
    public void Check(string s)
    {
        try { Parse(s); }
        catch (ArgumentNullException ex) { Log(ex); }
        // catch (NullReferenceException) used to be here
        var msg = "catch (NullReferenceException e)";
    }
}
