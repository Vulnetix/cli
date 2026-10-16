using System.IO;
using System.Text.Json;

namespace Acme.Config
{
    public static class FeatureFlags
    {
        public static bool IsEnabled(string path, string flag)
        {
            try
            {
                var doc = JsonDocument.Parse(File.ReadAllText(path));
                return doc.RootElement.GetProperty(flag).GetBoolean();
            }
~>            catch
            {
                return false;
            }
        }
    }
}
