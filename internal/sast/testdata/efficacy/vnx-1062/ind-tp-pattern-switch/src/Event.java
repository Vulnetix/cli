package ev;

public abstract class Event {
    public String describe() {
        return switch (this) {
~>            case Login l -> "login";
            default -> "other";
        };
    }
}
