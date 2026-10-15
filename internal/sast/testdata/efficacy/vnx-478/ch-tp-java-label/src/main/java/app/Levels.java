package app;

public class Levels {
    public String label(int level) {
        String label = null;
~>        switch (level) {
            case 1:
                label = "low";
                break;
            case 2:
                label = "medium";
                break;
            case 3:
                label = "high";
                break;
        }
        return label.toUpperCase();
    }
}
