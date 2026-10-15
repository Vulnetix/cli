def enter_jail(dir)
~>  Dir.chroot(dir)
  Process::Sys.setuid(65534)
end
