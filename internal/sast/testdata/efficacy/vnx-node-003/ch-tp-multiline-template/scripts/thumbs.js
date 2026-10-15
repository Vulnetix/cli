const { execSync } = require("child_process");

function thumbnail(input, size) {
~>  execSync(`convert \
    -resize ${size} \
    ${input} out.png`);
}

module.exports = thumbnail;
