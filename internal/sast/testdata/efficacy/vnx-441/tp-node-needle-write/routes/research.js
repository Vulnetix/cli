const needle = require("needle");

function ResearchHandler() {
    this.displayResearch = (req, res) => {
        if (req.query.symbol) {
            const url = req.query.url + req.query.symbol;
~>            return needle.get(url, (error, upstreamRes, body) => {
                res.writeHead(200, { "Content-Type": "text/html" });
                if (body) {
                    res.write(body);
                }
                return res.end();
            });
        }
        return res.render("research");
    };
}

module.exports = ResearchHandler;
