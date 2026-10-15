class Sync
  def call(params)
    options = { retries: 3 }
    options.update(params.slice(:timeout))
    form = SignupForm.new(params)
    payload = OpenStruct.new(params)
    stats = Hash.new(0)
    form.valid? && payload && stats
  end
end
