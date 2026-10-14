FROM ruby:3.3-slim
WORKDIR /app
~>ADD Gemfile Gemfile.lock /app/
RUN bundle install
~>ADD --chown=app:app . /app
~>ADD ["config/puma.rb", "/app/config/puma.rb"]
~>add   src/   /srv/src/
~>ADD --chmod=644 \
    config/nginx.conf \
    /etc/nginx/nginx.conf
CMD ["bundle", "exec", "puma"]
