package store

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *Store) PutItem(c *gin.Context) {
	var item Item
~>	if err := c.ShouldBind(&item); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	_, err := s.items.UpdateOne(c, bson.M{"_id": c.Param("id")}, bson.M{"$set": item})
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}

func (s *Store) AddItem(c *gin.Context) {
	item := new(Item)
~>	if err := c.BindJSON(item); err != nil {
		return
	}
	if _, err := s.items.InsertOne(c, item); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
	}
}
