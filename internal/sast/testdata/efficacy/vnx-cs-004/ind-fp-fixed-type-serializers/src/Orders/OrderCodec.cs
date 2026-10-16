using System.IO;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Web.Script.Serialization;
using System.Xml.Serialization;
using MessagePack;

namespace Orders
{
    public class OrderCodec
    {
        public Order FromXml(Stream body)
        {
            var xs = new XmlSerializer(typeof(Order));
            return (Order)xs.Deserialize(body);
        }

        public Invoice FromDataContract(Stream body)
        {
            var dcs = new DataContractSerializer(typeof(Invoice));
            return (Invoice)dcs.ReadObject(body);
        }

        public Order FromJson(string json) => JsonSerializer.Deserialize<Order>(json);

        public Order FromLegacyJson(string json) => new JavaScriptSerializer().Deserialize<Order>(json);

        public Order FromMsgPack(byte[] payload) => MessagePackSerializer.Deserialize<Order>(payload);
    }
}
