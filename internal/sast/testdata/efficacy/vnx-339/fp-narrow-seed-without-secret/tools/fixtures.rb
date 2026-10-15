class Fixtures
  def colours(names)
    srand(names.length)
    names.map { PALETTE.sample }
  end
end
