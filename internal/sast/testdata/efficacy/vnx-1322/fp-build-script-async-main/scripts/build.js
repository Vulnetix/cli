const fs = require('fs')
const { execSync } = require('child_process')

async function main(request) {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'))
  execSync('tsc -p .', { stdio: 'inherit' })
  fs.writeFileSync('dist/version.txt', pkg.version)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
