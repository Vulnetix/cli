class AddIdx < ActiveRecord::Migration[7.0]
  def up
    table = "users"
    execute "UPDATE #{table} SET active = true"
  end
end
