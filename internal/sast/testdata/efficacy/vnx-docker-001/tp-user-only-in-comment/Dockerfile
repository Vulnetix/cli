~>FROM ruby:3.3-slim
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install --without development test
COPY . .
# USER app   (re-enable once the volume permissions are fixed)
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
