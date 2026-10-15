class GitController < ApplicationController
  def log
    ref = params[:ref]
    out, _err, _s = Open3.capture3("git", "log", "--oneline", ref)
    lines, _ = Open3.capture2(
      "git", "show", "--stat", ref
    )
    safe, _ = Open3.capture2("git show #{Shellwords.escape(ref)}")
    n = params[:n].to_i
    head, _ = Open3.capture2("git log -n #{n}")
    render plain: out + lines + safe + head
  end
end
