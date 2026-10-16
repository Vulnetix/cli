package com.acme;
import javax.persistence.EntityManager;
import java.util.List;
public class Importer {
    private EntityManager em;
~>    protected void importAll(List<Row> rows) {
        Row first = em.find(Row.class, 1L);
        em.persist(rows.get(0));
        em.merge(rows.get(1));
        em.remove(first);
        em.createQuery("DELETE FROM Stale s").executeUpdate();
    }
}
