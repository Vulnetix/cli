package com.acme.store;

public class OrderRepository {
    public Order find(long id) {
        try {
            return jdbc.queryForObject("select * from orders where id = ?", mapper, id);
        } catch (Exception e) {
            log.error("lookup of order {} failed", id, e);
            return null;
        }
    }

    public void save(Order o) {
        try {
            jdbc.update("insert ...", o.id());
        } catch (RuntimeException e) {
            throw new RepositoryException("save failed", e);
        }
    }

    public void close() {
        try {
            pool.close();
        } catch (Throwable t) {
            metrics.recordFailure(t);
        }
    }

    public void shutdown() {
        try {
            pool.shutdown();
        } catch (Exception e) {
            throw e;
        }
    }
}
