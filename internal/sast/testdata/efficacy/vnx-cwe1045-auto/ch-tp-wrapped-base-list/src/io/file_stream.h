#pragma once

#include "io/stream.h"

namespace io {

class Stream {
 public:
  virtual ~Stream();
  virtual int read(char* buf, int n) = 0;
};

class FileStream
    : public Stream,
      private NonCopyable {
 public:
  explicit FileStream(int fd);
~>  ~FileStream();
  int read(char* buf, int n) override;

 private:
  int fd_;
};

}  // namespace io
