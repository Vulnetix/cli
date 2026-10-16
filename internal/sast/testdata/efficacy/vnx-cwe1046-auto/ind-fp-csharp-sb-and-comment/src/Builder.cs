using System.Text;

namespace Acme
{
    public class Builder
    {
        public string Build(string[] parts)
        {
            var sb = new StringBuilder();
            foreach (var p in parts)
            {
                sb.Append(p);
                // text += p;
            }
            string tail = "end";
            tail += "!";
            return sb.ToString() + tail;
        }
    }
}
