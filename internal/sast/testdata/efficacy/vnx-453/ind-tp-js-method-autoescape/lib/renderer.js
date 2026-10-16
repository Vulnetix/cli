const nunjucks = require('nunjucks');

class TemplateRenderer {
  constructor(dir) {
    this.dir = dir;
  }

~>  render(name, context, autoescape = false) {
    const env = new nunjucks.Environment(new nunjucks.FileSystemLoader(this.dir), { autoescape });
    return env.render(name, context);
  }
}

module.exports = TemplateRenderer;
