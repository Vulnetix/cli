class Note < ApplicationRecord
  # Never do: where("id = #{params[:id]}")
  def self.recent
    where("created_at > ?", 1.week.ago).order(:created_at)
  end
end
