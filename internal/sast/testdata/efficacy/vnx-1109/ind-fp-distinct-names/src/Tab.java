public class Tab {
    int total(int[][] m) {
        int t = 0;
        for (int i = 0; i < m.length; i++) {
            for (int j = 0; j < m[i].length; j++) {
                t += m[i][j];
            }
        }
        return t;
    }
}
