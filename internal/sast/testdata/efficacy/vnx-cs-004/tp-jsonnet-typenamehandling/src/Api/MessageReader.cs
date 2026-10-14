using System.IO;
using Newtonsoft.Json;

namespace Api
{
    public class MessageReader
    {
        public Message Read(string json)
        {
~>            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
            return JsonConvert.DeserializeObject<Message>(json, settings);
        }

        public object Stream(TextReader body)
        {
            var serializer = new JsonSerializer
            {
~>                TypeNameHandling = TypeNameHandling.Arrays,
            };
            return serializer.Deserialize(new JsonTextReader(body));
        }
    }
}
