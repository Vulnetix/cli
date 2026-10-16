Reporting.configure do |config|
  config.instance_eval do
    self.timezone = "UTC"
    self.export_formats = %i[csv pdf]
  end
end

ActiveSupport.on_load(:active_record) do
  class_eval do
    scope :recent, -> { where("created_at > ?", 30.days.ago) }
  end
end

module ReportHelpers
  module_eval <<~RUBY, __FILE__, __LINE__ + 1
    def report_title
      "Monthly report"
    end
  RUBY
end
