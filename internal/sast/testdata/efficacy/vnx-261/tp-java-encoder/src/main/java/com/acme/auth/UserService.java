package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.xml.bind.DatatypeConverter;

public class UserService {
    private final UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public void register(String username, String password) {
~>        String encoded = Base64.getEncoder().encodeToString(password.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        repo.save(new User(username, encoded));
    }

    public void changePassword(User user, ChangeRequest req) {
~>        user.setPassword(@@sample:D[a]ta[t]yp[e]Co[n]ve[r]te[r][.]p[r]in[t]Ba[s]e6[4]Bi[n]ar[y]@@(req.getNewPassword().getBytes()));
        repo.save(user);
    }
}
