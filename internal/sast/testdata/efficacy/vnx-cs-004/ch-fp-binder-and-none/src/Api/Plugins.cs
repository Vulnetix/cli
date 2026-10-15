using Newtonsoft.Json;

namespace App.Api;

public static class Plugins
{
    private static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
    {
        TypeNameHandling = TypeNameHandling.Objects,
        SerializationBinder = new KnownTypesBinder(new[] { typeof(PluginA), typeof(PluginB) }),
    };

    public static object Load(string json) => JsonConvert.DeserializeObject(json, Settings);

    public static object Plain(string json) =>
        JsonConvert.DeserializeObject(json, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None });
}
