require 'digest'

describe User do
  it 'stores the legacy password hash' do
    expect(user.password).to eq(Digest::MD5.hexdigest('secret'))
  end
end
