using System;

namespace Acme.Core
{
    public class Defaults
    {
        public static readonly string Region = "eu-west-1";
        public const int PageSize = 50;
        public static string CurrentUser { get; set; }
        public static string Environment => "production";
        public static event EventHandler Changed;
        private static int counter;

        public static void Reset()
        {
            counter = 0;
        }
    }
}
