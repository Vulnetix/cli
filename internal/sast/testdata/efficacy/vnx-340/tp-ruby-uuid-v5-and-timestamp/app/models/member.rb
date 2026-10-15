class Member < ApplicationRecord
  NS = "@@sample:6[b]a7[b]81[1][-]9[d]ad[-]11[d]1[-][8]0b[4][-]0[0]c0[4]fd[4]30[c]8@@"

  def issue_tokens
~>    self.confirmation_token = Digest::UUID.uuid_v5(NS, email)
~>    self.api_token = UUIDTools::UUID.timestamp_create.to_s
  end
end
