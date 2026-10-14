package a

import "example.com/app/internal/b"

func A() int { return b.B() + 1 }
