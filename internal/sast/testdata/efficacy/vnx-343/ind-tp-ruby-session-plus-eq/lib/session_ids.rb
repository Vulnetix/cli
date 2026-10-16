class SessionIds
  def initialize
    @session_id = 10_000
  end

  def advance!
~>    @session_id += rand(1..300)
    @session_id
  end
end
