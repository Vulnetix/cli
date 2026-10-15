module CsrfHelpers
  def self.included(base)
    base.class_eval do
      skip_before_action :verify_authenticity_token
    end
  end
end
