#pragma once
#include <QObject>
#include <QTimer>

class Worker : public QObject {
    Q_OBJECT
public:
    explicit Worker(QObject* parent = nullptr) : QObject(parent), timer_(new QTimer) {}
    ~Worker() override { delete timer_; }

private:
    QTimer* timer_;
};
