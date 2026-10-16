require "json"
require_relative "report_base"

module ReportLoader
  KINDS = %w[sales inventory].freeze

  def self.load_kind(kind)
    raise ArgumentError, "unknown report" unless KINDS.include?(kind)

    require_relative "reports/#{kind}_report"
  end

  def self.load_configured
    require File.join(__dir__, "reports", Settings.reports.default_kind)
  end
end
