class User < ApplicationRecord
  NAMESPACE = '@@sample:9[a]1c[8]f4[0][-]5[a]6b[-]4c[3]e[-][8]d2[f][-]0[b]1e[2]c3[d]4e[5]f@@'

  def start_reset!
~>    self.reset_password_token = Digest::UUID.uuid_v5(NAMESPACE, email)
    save!
  end
end
