module FsHelper
  def make_shared(dir)
    FileUtils.mkdir_p(dir)
    FileUtils.chmod(0777, dir)
  end
end
