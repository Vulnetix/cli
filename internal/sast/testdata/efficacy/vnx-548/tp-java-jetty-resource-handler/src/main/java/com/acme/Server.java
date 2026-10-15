public class Server {
    public static void main(String[] args) throws Exception {
        ResourceHandler files = new ResourceHandler();
~>        files.setDirectoriesListed(true);
        files.setResourceBase("/srv/files");
    }
}
