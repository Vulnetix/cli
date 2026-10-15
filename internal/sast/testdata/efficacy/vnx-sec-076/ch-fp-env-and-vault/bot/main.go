package main

import (
	"os"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func main() {
	bot, _ := tgbotapi.NewBotAPI(os.Getenv("TELEGRAM_BOT_TOKEN"))
	_ = bot
}
