class Issuer
  def self.issue(user, secret)
    JWT.encode({ user_id: user.id, exp: @@sample:1[.]ho[u]r[.][f]ro[m][_]n[o]w[.][t]o[_][i]@@ }, secret, 'HS256')
  end
end
