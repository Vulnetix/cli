module ProfileHelper
  def sanitized_bio(bio)
    return "" if bio.blank?

~>    text = bio.gsub(/<script.*?>.*?<\/script>/m, "")
~>    text = text.gsub("<iframe", "")
    text.strip
  end

  def safe_website(url)
~>    return nil if url =~ /\Ajavascript:/
    url
  end
end
