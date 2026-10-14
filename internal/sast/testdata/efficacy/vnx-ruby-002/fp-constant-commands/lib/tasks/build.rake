namespace :assets do
  task :build do
    revision = `git rev-parse HEAD`.strip
    system("yarn build")
    sh "bin/webpack --mode production"
    puts "built #{revision} for #{ENV.fetch('RAILS_ENV', 'development')}"
    out = %x(git log -1 --format=%cd)
    total = eval("1 + 2")
    params = { verbose: true }
    system("make", "dist")
  end
end
