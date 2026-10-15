package app;

import java.util.Base64;

public class CredentialStore {
    public void save(User user, String password) throws Exception {
~>        user.setPassword(Base64.getEncoder().encodeToString(password.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@)));
~>        byte[] enc = cipher.doFinal(user.getPassword().getBytes());
        repo.save(user);
    }
}
