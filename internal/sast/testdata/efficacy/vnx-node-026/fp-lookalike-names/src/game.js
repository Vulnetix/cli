function spawnEnemy(type, opts) {
  return { type, ...opts };
}

const turtle = spawnEnemy(enemyType, { shell: true, speed: 2 });
const config = { shell: true };
const prompt = respawn(level, { shell: 'zsh' });

module.exports = { turtle, config, prompt };
