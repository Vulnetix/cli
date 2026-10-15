using System.Linq;
using System.Text;

namespace Acme.Services
{
    public class Greeter
    {
        public string Greet(string[] names)
        {
            string greeting = "Hello";
            greeting += ", " + string.Join(", ", names);
            var sb = new StringBuilder();
            foreach (var n in names)
            {
                sb.Append(n);
                string line = "Hi " + n;
                line += "!";
            }
            int count = 0;
            foreach (var n in names)
            {
                count += n.Length;
            }
            return greeting + sb + count;
        }
    }
}
