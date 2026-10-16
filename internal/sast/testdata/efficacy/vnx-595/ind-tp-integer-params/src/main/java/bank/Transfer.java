package bank;

public class Transfer {
    boolean sameAccount(Integer fromId, Integer toId) {
~>        return fromId == toId;
    }

    boolean different(Long a, Long b) {
~>        return a != b;
    }
}
