namespace :release do
  task :push do
~>    ENV["GEM_HOST_API_KEY"] ||= "rubygems_@@sample:[0-9a-f]{48}@@"
    sh "gem push pkg/acme-#{Acme::VERSION}.gem"
  end
end
