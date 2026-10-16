namespace Acme
{
    public class Joiner
    {
        public string Join(string[] parts)
        {
            string result = string.Empty;
            for (int i = 0; i < parts.Length; i++)
            {
~>                result += parts[i] + ";";
            }
            return result;
        }
    }
}
