package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
)

func FiberSave(c *fiber.Ctx) error {
	file, err := c.FormFile("avatar")
	if err != nil {
		return err
	}
~>	return c.SaveFile(file, "./public/avatars/"+file.Filename)
}

func GinSave(c *gin.Context) {
	f, _ := c.FormFile("attachment")
	folder := c.PostForm("folder")
~>	c.SaveUploadedFile(f, "/data/"+folder+"/attachment.bin")
	c.Status(http.StatusOK)
}
