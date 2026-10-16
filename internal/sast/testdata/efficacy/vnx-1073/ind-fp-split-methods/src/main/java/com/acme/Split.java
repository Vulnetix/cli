package com.acme;
public class Split {
    OrderRepository repo;
    public Order a(long id) {
        repo.findById(id);
        repo.findByUserId(id);
        return repo.findAll().get(0);
    }
    public void b(Order o) {
        repo.save(o);
        repo.save(o);
        repo.deleteById(1L);
    }
    public long c() {
        return repo.count();
    }
}
