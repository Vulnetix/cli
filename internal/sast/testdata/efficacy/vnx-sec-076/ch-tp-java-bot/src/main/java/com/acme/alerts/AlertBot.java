package com.acme.alerts;

import org.telegram.telegrambots.bots.TelegramLongPollingBot;

public class AlertBot extends TelegramLongPollingBot {
    @Override
    public String getBotToken() {
~>        return "@@sample:[5-7][0-9]{9}:AA[A-Za-z0-9_-]{33}@@";
    }
}
