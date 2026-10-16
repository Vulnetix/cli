import java.nio.file.*;
import java.util.*;
import javax.persistence.criteria.*;

class Paths2 {
    String build(List<String> parts) {
        String s = String.join("/", parts);
        String t = String.join(",", "a", "b");
        Path p = Paths.get("a").resolve("b");
        return s + t + p;
    }
    void q(CriteriaBuilder cb, Root<Order> r) {
        r.join("customer").join("address").join("country").join("region").join("zone").join("code");
    }
}
