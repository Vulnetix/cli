class Report < ApplicationRecord
  %w[draft published archived].each do |state|
    class_eval <<~RUBY, __FILE__, __LINE__ + 1
      def #{state}?
        status == "#{state}"
      end
    RUBY
  end

  def self.filtered(params)
    where(status: params[:status]).instance_eval { order(:created_at) }
  end
end
