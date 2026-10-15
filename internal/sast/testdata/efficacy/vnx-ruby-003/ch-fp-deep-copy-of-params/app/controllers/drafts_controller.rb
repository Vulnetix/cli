class DraftsController < ApplicationController
  def create
    snapshot = Marshal.load(Marshal.dump(params.to_unsafe_h))
    copy = Marshal.load(Marshal.dump(draft_params))
    Draft.create!(data: snapshot, copy: copy)
  end
end
