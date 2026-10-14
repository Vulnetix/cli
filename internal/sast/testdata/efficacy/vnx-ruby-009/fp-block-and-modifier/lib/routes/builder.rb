module Routes
  class Builder
    VERBS = %w[get post].freeze

    def define(app)
      VERBS.each do |verb|
        app.send(verb, "/items/:id") { params[:id] }
        app.send(verb) { params[:a] }
        app.public_send(verb) if params[:enabled]
      end
    end
  end
end
