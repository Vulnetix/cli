using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Newtonsoft.Json;

namespace Export
{
    public class SnapshotWriter
    {
        public void Write(Stream output, Snapshot snapshot)
        {
            var formatter = new BinaryFormatter();
            formatter.Serialize(output, snapshot);
        }

        public string ToJson(Snapshot snapshot)
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All, Formatting = Formatting.Indented };
            return JsonConvert.SerializeObject(snapshot, settings);
        }
    }
}
