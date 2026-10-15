const { Telegraf } = require('telegraf');

~>const bot = new Telegraf('@@sample:[0-9]{10}@@:AA@@sample:[A-Za-z0-9_-]{33}@@');
bot.launch();
