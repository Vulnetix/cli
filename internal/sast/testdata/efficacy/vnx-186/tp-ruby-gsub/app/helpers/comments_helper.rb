module CommentsHelper
  def scrub(body)
~>    body.gsub(/<script>.*?<\/script>/m, "")
  end

  def scrub_url(url)
~>    url.sub("javascript:", "")
  end
end
