class Price {
    static int? Total(int? price, int? tax) {
~>        return price + tax ?? 0;
    }
}
