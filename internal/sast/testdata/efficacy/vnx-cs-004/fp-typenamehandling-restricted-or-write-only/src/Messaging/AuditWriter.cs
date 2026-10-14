using Newtonsoft.Json;

namespace Messaging
{
    public class AuditWriter
    {
        public string Write(object evt)
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All, Formatting = Formatting.Indented };
            return JsonConvert.SerializeObject(evt, settings);
        }
    }
}
