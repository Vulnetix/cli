public static class Greeter
{
    public static string Hello(string name)
    {
~>        return "Hello, " + name ?? "guest";
    }
}
