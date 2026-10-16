package sec;

import jakarta.persistence.Entity;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
public class AppUser implements UserDetails {
    private String username;
}
