using Newtonsoft.Json;

namespace App.Export;

public static class Snapshot
{
    public static string Write(object state)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };
        return JsonConvert.SerializeObject(state, settings);
    }

    public static State Read(string json) => JsonConvert.DeserializeObject<State>(json)!;
}
