module Jail
  def self.enter(root)
~>    Dir.chroot(root)
    Process::Sys.setuid(65534)
  end
end
