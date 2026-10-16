package g;

public class Doc {
    String help = "usage: @param name and @return value";

    /**
     * Fetches.
     * @param id the id
     * @return the thing
     */
    public String fetch(String id) { return help; }

    /**
     * Multi-line signature.
     * @param name the name
     * @param tags the tags
     */
    @SuppressWarnings({
        "unchecked", "rawtypes"
    })
    public void tag(String name,
                    java.util.Map<String, String> tags) { }
}
