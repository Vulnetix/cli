package imagesrc

import "runtime"

// hostArch is the image architecture that runs natively here.
func hostArch() string {
	return runtime.GOARCH
}
