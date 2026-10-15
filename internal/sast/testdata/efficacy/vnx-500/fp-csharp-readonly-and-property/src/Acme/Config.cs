namespace Acme
{
    public static class Config
    {
        public static readonly string Name = "acme";
        public const int Limit = 5;
        public static string Mode { get; set; } = "basic";
        public static string Describe() => "config";
        public static int Twice(int x) => x * 2;
        public static event EventHandler Changed;
        private static int counter;
    }
}
