module.exports = {
  apps: [{
    name: 't3mp3st-portal',
    script: 'src/server.js',
    instances: 1,
    exec_mode: 'fork',
    autorestart: true,
    watch: false,
    env: { PORT: 8888, NODE_ENV: 'production' },
  }],
};
