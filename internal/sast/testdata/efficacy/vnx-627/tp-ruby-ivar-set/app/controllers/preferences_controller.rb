class PreferencesController < ApplicationController
  def update
~>    instance_variable_set("@#{params[:field]}", params[:value])
    render json: { ok: true }
  end

  def show
    field = params[:field]
~>    value = instance_variable_get("@#{field}")
    render json: { value: value }
  end

  def import
    params[:prefs].each do |key, val|
~>      instance_variable_set("@#{key}", val)
    end
  end
end
