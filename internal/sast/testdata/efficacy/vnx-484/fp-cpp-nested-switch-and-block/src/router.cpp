int route(int a, int b) {
    switch (a) {
        case 1: {
            int x = b * 2;
            return x;
        }
        case 2:
            switch (b) {
                case 1:
                    return 3;
                default:
                    return 4;
            }
        default:
            return 0;
    }
}
