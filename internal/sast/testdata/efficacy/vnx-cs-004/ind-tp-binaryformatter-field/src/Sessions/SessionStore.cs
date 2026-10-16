using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.Extensions.Caching.Distributed;

namespace Sessions
{
    public class SessionStore
    {
        private readonly IDistributedCache _cache;
        private readonly IFormatter _formatter = new BinaryFormatter();

        public SessionStore(IDistributedCache cache) => _cache = cache;

        public UserSession Get(string sessionId)
        {
            var bytes = _cache.Get("session:" + sessionId);
            if (bytes == null) return null;
            using var ms = new MemoryStream(bytes);
~>            return (UserSession)_formatter.Deserialize(ms);
        }

        public object FromSoap(Stream body)
        {
            var sf = new System.Runtime.Serialization.Formatters.Soap.SoapFormatter();
~>            return sf.Deserialize(body);
        }

        public object FromNetDataContract(Stream body)
        {
            var ndcs = new NetDataContractSerializer();
~>            return ndcs.ReadObject(body);
        }
    }
}
