using System.Collections.Generic;
using System.Text;

public class Csv
{
    public string Join(List<string> items)
    {
        var sb = new StringBuilder();
        int total = 0;
        foreach (var item in items)
        {
            sb.Append(item).Append(',');
            total += item.Length;
        }
        string line = "";
        line += sb.ToString();
        return line;
    }
}
