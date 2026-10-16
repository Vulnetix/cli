require 'yaml'

FEATURES = YAML.load_file(Rails.root.join("config", "features.yml"))
LOCALES = YAML.load(File.read(Rails.root.join("config", "locales.yml")))
DEFAULTS = YAML.load(<<~YML)
  retries: 3
  timeout: 10
YML

# YAML.load(request.body.read) must never be used
