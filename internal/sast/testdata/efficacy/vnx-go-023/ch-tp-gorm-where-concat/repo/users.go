package repo

import "gorm.io/gorm"

type User struct {
	ID   uint
	Name string
}

func ByName(db *gorm.DB, name string) ([]User, error) {
	var users []User
~>	err := db.Where("name = '" + name + "'").Find(&users).Error
	return users, err
}
