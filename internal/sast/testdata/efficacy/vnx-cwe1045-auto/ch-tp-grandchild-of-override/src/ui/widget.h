#pragma once

namespace ui {

class Widget {
 public:
  virtual ~Widget() = default;
  virtual void draw() = 0;
};

class Button : public Widget {
 public:
  ~Button() override;
  void draw() override;
};

class IconButton : public Button {
 public:
~>  ~IconButton();
  void draw() override;
};

}  // namespace ui
