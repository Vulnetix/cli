using RabbitMQ.Client;
using StackExchange.Redis;

namespace Messaging
{
    public static class Connections
    {
        public static IConnection Broker()
        {
            var factory = new ConnectionFactory
            {
                HostName = "rabbit.internal",
                UserName = "orders",
~>                Password = "Rabb1t-Orders",
            };
            return factory.CreateConnection();
        }

        public static ConnectionMultiplexer Cache()
        {
            var options = ConfigurationOptions.Parse("cache.internal:6380");
~>            options.Password = "Cache-Opt-Pw";
            options.Ssl = true;
            return ConnectionMultiplexer.Connect(options);
        }

        public static ConnectionMultiplexer Sessions()
        {
~>            var options = new ConfigurationOptions { EndPoints = { "sessions:6379" }, Password = "Sess-Opt-Pw" };
            return ConnectionMultiplexer.Connect(options);
        }
    }
}
