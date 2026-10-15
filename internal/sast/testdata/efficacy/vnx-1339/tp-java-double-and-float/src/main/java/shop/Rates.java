package shop;

public class Rates {
    public boolean isPromo(double rate, float amount) {
~>        if (rate == 0.05) {
            return true;
        }
~>        return amount != 19.99f;
    }
}
