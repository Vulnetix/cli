package reg;

public class Registry {
    private static final Client CLIENT;
    private static final Cache CACHE;

    static {
~>        CLIENT = new Client(new Config("prod"));
~>        CACHE = new Cache(CLIENT, 128);
    }
}
