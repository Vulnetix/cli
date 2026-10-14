class HelpText
  # never write User.where("id = #{params[:id]}")
  def self.tip(params)
    "Avoid where(\"id = #{params[:id]}\") in controllers"
  end

  def self.choose(options, params)
    options.select { |o| o.name == params[:name] }
    options.group_by(&:kind)
    Thread.new { executor.execute(params[:job]) }
  end
end
