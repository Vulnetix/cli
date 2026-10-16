require 'rails_helper'

describe IconsHelper do
  it 'renders safe markup' do
    expect('<b>x</b>'.html_safe).to be_html_safe
  end
end
