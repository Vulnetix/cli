class SyncService
  def call(params)
    @user.update(name: params[:name])
    options.update(params)
    headers.update(params[:headers])
    record = Record.create(title: "fixed", count: 1)
    record.update(status: :done)
  end
end
