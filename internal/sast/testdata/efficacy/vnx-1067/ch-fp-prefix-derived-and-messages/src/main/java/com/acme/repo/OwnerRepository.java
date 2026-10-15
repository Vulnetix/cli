package com.acme.repo;

import java.util.List;
import org.springframework.data.repository.Repository;

public interface OwnerRepository extends Repository<Owner, Integer> {
    List<Owner> findByLastNameStartingWith(String prefix);

    List<Owner> findByCityAndActiveTrue(String city);

    default String hint() {
        String containing = "use findByNameContaining sparingly";
        String pct = "%" + containing;
        return String.format("%d%% of searches LIKE '%s'", 3, pct);
    }
}
