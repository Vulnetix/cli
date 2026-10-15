CREATE INDEX users_city_idx ON users (city);
CREATE INDEX users_country_idx ON users (country);
CREATE INDEX users_plan_idx ON users (plan);
CREATE INDEX users_created_idx ON users (created_at);
CREATE INDEX IF NOT EXISTS users_name_idx ON users (name);
CREATE INDEX users_plan_city_idx ON users (plan, city);
CREATE INDEX users_country_plan_idx ON users (country, plan);
CREATE INDEX users_email_lower_idx ON users (lower(email));
