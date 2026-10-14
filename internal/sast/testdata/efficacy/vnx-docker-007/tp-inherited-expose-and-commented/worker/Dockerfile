~>FROM ruby:3.3-slim
WORKDIR /app
COPY . .
RUN bundle install
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
