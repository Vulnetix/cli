module AttributeMacros
  def flag(name)
    class_eval <<~RUBY, __FILE__, __LINE__ + 1
      def #{name}?
        !!@#{name}
      end
    RUBY
  end

  def configure(params)
    instance_eval do
      @settings = params.dup
    end
    instance_eval { @ready = true }
  end
end
