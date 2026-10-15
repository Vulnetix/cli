class WorkInfoController < ApplicationController
  def index
~>    @user = User.find_by(id: params[:user_id])
  end

  def show
~>    @pay = Paystub.find(params[:id])
  end

  def destroy
    record_id = params[:record_id]
~>    Record.destroy(record_id)
  end
end
