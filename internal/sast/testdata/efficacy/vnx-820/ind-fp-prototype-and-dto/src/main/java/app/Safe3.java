package app;
import java.util.ArrayList;
import java.util.List;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;
@Component
@Scope("prototype")
public class Safe3 {
    private int n;
    private List<String> items = new ArrayList<>();
    public void add(String s) { n++; items.add(s); }
}
