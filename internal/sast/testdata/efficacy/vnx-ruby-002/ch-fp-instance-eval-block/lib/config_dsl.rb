class ConfigDsl
  def self.build(params, &block)
    dsl = new(params)
    dsl.instance_eval(&block)
    dsl.instance_eval do
      @name = params[:name]
    end
    dsl
  end
end
