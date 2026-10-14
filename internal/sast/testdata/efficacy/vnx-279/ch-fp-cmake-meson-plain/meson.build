project('tool', 'c')

executable('tool', 'tool.c',
  install : true,
  install_mode : 'rwxr-xr-x',
)

install_data('shared.conf', install_mode : ['rw-rw-r--', 'root', 'staff'])
install_emptydir('/var/lib/tool', install_mode : 'rwxrwsr-x')
