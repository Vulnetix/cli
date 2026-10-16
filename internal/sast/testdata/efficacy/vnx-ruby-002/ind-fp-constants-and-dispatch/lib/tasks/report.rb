REPORTS = {
  "daily" => "daily_report",
  "weekly" => "weekly_report"
}.freeze

class ReportRunner
  def run(kind)
    method_name = REPORTS.fetch(kind)
    send(method_name)
  end

  def uptime
    `uptime`.strip
  end

  def build
    system("bundle exec rake assets:precompile")
    # eval(params[:expression]) would be terrible
    msg = "do not call system(\"rm #{params[:x]}\")"
    puts msg
  end

  def dispatch(action)
    public_send("#{action}_report") if %w[daily weekly].include?(action)
  end
end
