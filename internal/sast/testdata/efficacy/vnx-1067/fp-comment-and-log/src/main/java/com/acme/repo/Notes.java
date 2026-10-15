package com.acme.repo;

public class Notes {
    // avoid: WHERE name LIKE '%x%' scans the whole table
    /*
     * ps.setString(1, "%" + q + "%");
     */
    void log() {
        System.out.println("progress: 50%");
    }
}
