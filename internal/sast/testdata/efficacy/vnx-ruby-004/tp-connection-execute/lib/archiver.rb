class Archiver
  def purge(params)
    table = params[:table]
~>    ActiveRecord::Base.connection.execute("DELETE FROM #{table} WHERE archived = true")
~>    rows = ActiveRecord::Base.connection.select_all("SELECT * FROM audits WHERE actor = '#{params[:actor]}'")
    rows.to_a
  end
end
