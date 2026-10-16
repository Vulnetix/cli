package ejb;

import javax.ejb.Stateless;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Stateless
public class ReportBean {
    public void generate(String id) {
~>        new Thread(() -> render(id)).start();
    }

    public void pool() {
~>        ExecutorService ex = Executors.newFixedThreadPool(4);
    }

    private void render(String id) { }
}
