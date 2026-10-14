workers Integer(ENV.fetch("WEB_CONCURRENCY", 2))
bind "unix:///run/app/puma.sock"

on_worker_boot do
~>  File.umask(0000)
end
