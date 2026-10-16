module Jail
  def self.enter(root)
    Dir.chroot(root)
    Dir.chdir("/")
  end
end
