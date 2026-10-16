require 'open3'

module Build
  VERSION_CMD = "git describe --tags".freeze

  def self.version
    out, _st = Open3.capture2(VERSION_CMD)
    out.strip
  end

  def self.compile
    # Open3.capture3("make #{params[:target]}") was removed
    Open3.capture3("make", "all")
    note = "Open3.popen3(\"x #{params[:y]}\")"
    puts note
  end

  def self.status
    Open3.capture2e("git status --short")
  end
end
