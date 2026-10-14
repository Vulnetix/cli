class BackfillTotals < ActiveRecord::Migration[7.1]
  def up(table = "orders")
    execute("UPDATE #{table} SET total = subtotal + tax")
  end
end
