package repo;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByNameStartingWith(String p);
    List<User> findByEmail(String email);
    User findByIdAndActiveTrue(Long id);
}
