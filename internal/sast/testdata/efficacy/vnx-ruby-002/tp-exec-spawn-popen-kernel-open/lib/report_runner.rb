class ReportRunner
  def initialize(request)
    @request = request
  end

  def run
    @fmt = @request.params["format"]
~>    pid = Process.spawn("render-report --format=#{@fmt}")
    Process.wait(pid)
  end

  def export(params)
    target = params[:target]
~>    IO.popen("tar czf /tmp/out.tgz #{target}") { |io| io.read }
  end

  def fetch(params)
~>    open(params[:source]).read
  end

  def replace(params)
~>    exec "convert #{params[:file]} /tmp/thumb.png"
  end
end
