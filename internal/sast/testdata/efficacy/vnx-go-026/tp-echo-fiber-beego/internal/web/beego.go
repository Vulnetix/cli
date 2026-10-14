package web

import "github.com/beego/beego/v2/server/web"

type UploadController struct{ web.Controller }

func (this *UploadController) Post() {
	_, h, err := this.GetFile("file")
	if err != nil {
		this.Abort("400")
	}
~>	this.SaveToFile("file", "static/upload/"+h.Filename)
}
