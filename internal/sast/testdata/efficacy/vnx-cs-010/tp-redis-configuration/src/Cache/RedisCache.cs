using StackExchange.Redis;

namespace Cache
{
    public static class RedisCache
    {
        public static ConnectionMultiplexer Connect()
        {
~>            return ConnectionMultiplexer.Connect("cache.internal:6380,password=R3dis-Cache-Key,ssl=True,abortConnect=False");
        }

~>        private const string Sessions = "sessions.internal:6379,password=S3ss10n-Store";
    }
}
