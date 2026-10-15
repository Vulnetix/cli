using System.Text;

namespace Generators
{
    public static class HashSnippetWriter
    {
        public static string Banner()
        {
            var sb = new StringBuilder();
            sb.AppendLine("// legacy compatibility shim removed in v4");
            sb.AppendLine("// var h = MD5.Create(); was used before");
            sb.Append(@"// new SHA1Managed() is forbidden by policy");
            return sb.ToString();
        }
    }
}
