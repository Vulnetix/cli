package com.acme;
public class Small {
    UserRepository userRepository; JdbcTemplate jdbcTemplate;
    public User load(long id) {
        User u = userRepository.findById(id);
        jdbcTemplate.update("UPDATE u SET seen = now() WHERE id = ?", id);
        userRepository.save(u);
        userRepository.countByActive(true);
        return u;
    }
}
