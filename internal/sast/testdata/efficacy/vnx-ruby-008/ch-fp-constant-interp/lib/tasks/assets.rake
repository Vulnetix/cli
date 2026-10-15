namespace :assets do
  task :compress do
    Open3.capture3("tar czf #{Rails.root}/tmp/assets.tgz public/assets")
  end
end
