using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;
using System.Web.Script.Serialization;
using System.Xml.Serialization;
using Newtonsoft.Json;

namespace Cache
{
    public class Snapshot
    {
        public byte[] Write(object value)
        {
            using var ms = new MemoryStream();
            BinaryFormatter bf = new BinaryFormatter();
            bf.Serialize(ms, value);
            return ms.ToArray();
        }

        public Order Json(string body)
        {
            var a = new JavaScriptSerializer().Deserialize<Order>(body);
            var b = JsonConvert.DeserializeObject<Order>(body);
            var c = JsonConvert.DeserializeObject<Order>(body, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None });
            var d = System.Text.Json.JsonSerializer.Deserialize<Order>(body);
            return a ?? b ?? c ?? d;
        }

        public Order Xml(Stream body)
        {
            var xs = new XmlSerializer(typeof(Order));
            var dcs = new DataContractSerializer(typeof(Order));
            var named = new XmlSerializer(Type.GetType("Shop.Order, Shop"));
            return (Order)xs.Deserialize(body) ?? (Order)dcs.ReadObject(body) ?? (Order)named.Deserialize(body);
        }
    }
}
