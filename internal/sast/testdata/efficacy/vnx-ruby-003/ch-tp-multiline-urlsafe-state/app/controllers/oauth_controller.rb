class OauthController < ApplicationController
  def callback
~>    state = Marshal.load(
      @@sample:B[a]se[6]4[.][u]rl[s]af[e][_]d[e]co[d]e6[4]@@(params[:state])
    )
    redirect_to state[:return_to]
  end
end
