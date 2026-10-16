using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Workflow
{
    public sealed class KnownStepsBinder : ISerializationBinder
    {
        private static readonly Dictionary<string, Type> Allowed = new()
        {
            ["approve"] = typeof(ApproveStep),
            ["notify"] = typeof(NotifyStep),
        };

        public Type BindToType(string assemblyName, string typeName) =>
            Allowed.TryGetValue(typeName, out var t) ? t : throw new JsonSerializationException("unknown step");

        public void BindToName(Type serializedType, out string assemblyName, out string typeName)
        {
            assemblyName = null;
            typeName = serializedType.Name.ToLowerInvariant().Replace("step", "");
        }
    }

    public class StepSerializer
    {
        private static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.Auto,
            SerializationBinder = new KnownStepsBinder(),
        };

        private static readonly JsonSerializerSettings Plain = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None,
        };

        public Step Read(string json) => JsonConvert.DeserializeObject<Step>(json, Settings);

        public Step ReadPlain(string json) => JsonConvert.DeserializeObject<Step>(json, Plain);
    }
}
