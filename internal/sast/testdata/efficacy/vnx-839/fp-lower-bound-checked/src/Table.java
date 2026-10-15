class Table {
    String get(HttpServletRequest request) {
        int row = Integer.parseInt(request.getParameter("row"));
        if (row >= 0 && row < rows.length) {
            return rows[row];
        }
        int col = Math.max(0, Integer.parseInt(request.getParameter("col")));
        if (col < cols.length) {
            return cols[col];
        }
        return null;
    }
}
