public class Scan {
    int count(int[][] cells) {
        int i;
        int n = 0;
        for (i = 0; i < cells.length; i++) {
~>            for (i = 0; i < cells[0].length; i++) {
                n += cells[i][i];
            }
        }
        return n;
    }
}
