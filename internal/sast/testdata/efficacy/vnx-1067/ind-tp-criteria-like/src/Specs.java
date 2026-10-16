package repo;

import javax.persistence.criteria.*;

public class Specs {
    Predicate nameMatches(CriteriaBuilder cb, Root<Customer> root, String q) {
~>        return cb.like(root.get("name"), "%" + q + "%");
    }
}
