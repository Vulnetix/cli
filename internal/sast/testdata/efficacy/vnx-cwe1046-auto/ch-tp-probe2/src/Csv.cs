using System.Collections.Generic;

public class Csv
{
    public string Join(List<string> items)
    {
        var line = "";
        foreach (var item in items)
        {
~>            line = line + item + ",";
        }
        return line;
    }
}
