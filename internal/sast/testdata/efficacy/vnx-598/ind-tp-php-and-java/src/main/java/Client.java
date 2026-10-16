public class Client {
    String build(String host, String sessionid) {
~>        return "https://" + host + "/view?sessionid=" + sessionid;
    }
}
