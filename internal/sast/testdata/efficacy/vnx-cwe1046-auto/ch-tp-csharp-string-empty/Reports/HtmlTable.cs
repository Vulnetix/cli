using System.Collections.Generic;

namespace Acme.Reports
{
    public static class HtmlTable
    {
        public static string Render(IEnumerable<string> rows)
        {
            var html = string.Empty;
            foreach (var row in rows)
            {
~>                html += $"<tr><td>{row}</td></tr>";
            }
            string footer = "";
            var i = 0;
            while (i < 5)
            {
~>                footer = footer + "<hr/>";
                i++;
            }
            return html + footer;
        }
    }
}
