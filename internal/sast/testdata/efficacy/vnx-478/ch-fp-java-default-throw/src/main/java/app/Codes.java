package app;

public class Codes {
    public String text(int code) {
        String text = null;
        switch (code) {
            case 200:
                text = "OK";
                break;
            case 404:
                text = "Not Found";
                break;
            default:
                throw new IllegalArgumentException("code " + code);
        }
        return text.trim();
    }

    public String other(int code) {
        String text = null;
        switch (code) {
            case 1:
                text = "one";
                break;
        }
        if (text == null) {
            return "";
        }
        return text.trim();
    }
}
