require "digest"

module Importer
  class Dedupe
    def initialize(store)
      @store = store
    end

    def seen?(row)
~>      key = Digest::MD5.hexdigest(row.values.join("|"))
      return true if @store.include?(key)

      @store << key
      false
    end
  end
end
