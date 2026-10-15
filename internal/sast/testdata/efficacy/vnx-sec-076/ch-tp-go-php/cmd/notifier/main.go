package main

import tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

func main() {
~>	bot, err := tgbotapi.NewBotAPI("@@sample:[1-9][0-9]{8}:AA[A-Za-z0-9_-]{33}@@")
	if err != nil {
		panic(err)
	}
	_ = bot
}
