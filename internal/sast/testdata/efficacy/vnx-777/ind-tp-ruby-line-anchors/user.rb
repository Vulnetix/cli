class Account < ApplicationRecord
~>  validates_format_of :handle, with: /^[a-z0-9_]+$/i
end
