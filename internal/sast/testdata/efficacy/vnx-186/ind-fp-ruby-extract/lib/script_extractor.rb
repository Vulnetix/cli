class ScriptExtractor
  SCRIPT_SRC = /<script[^>]+src="([^"]+)"/i

  def initialize(html)
    @html = html
  end

  # Returns every external script the page loads, for the asset audit.
  def sources
    @html.scan(SCRIPT_SRC).flatten
  end

  def first_inline
    m = @html.match(/<script>(.*?)<\/script>/m)
    m && m[1]
  end
end
