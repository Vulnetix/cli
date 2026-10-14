package upload

import "log"

// Example of what not to do:
//
//	file, h, _ := r.FormFile("f")
//	os.Create("./public/" + h.Filename)
func explain() {
	log.Println(`c.SaveUploadedFile(file, "./public/"+file.Filename) skips type checks`)
}
