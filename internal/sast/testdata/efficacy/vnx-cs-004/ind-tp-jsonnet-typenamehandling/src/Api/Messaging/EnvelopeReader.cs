using Newtonsoft.Json;

namespace Api.Messaging
{
    public class EnvelopeReader
    {
        public object Read(string message)
        {
            var settings = new JsonSerializerSettings
            {
~>                TypeNameHandling = TypeNameHandling.Objects,
                MissingMemberHandling = MissingMemberHandling.Ignore,
            };
            return JsonConvert.DeserializeObject(message, settings);
        }
    }
}
