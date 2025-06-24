module.exports = {
    apps: [{
      name: "node-app",
      script: "src/index.js",
      instances: "max",
      autorestart: true,
      watch: false,
      env: {
        NODE_ENV: "production",
        PORT: 9000
      }
    }]
  };