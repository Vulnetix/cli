package load

import (
	"bufio"
	"os"
	"strings"
)

type User struct{ Name, Email string }

func LoadUsers() ([]User, error) {
	f, err := os.Open("data/users.csv")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []User
	sc := bufio.NewScanner(f)
	for sc.Scan() {
~>		fields := strings.Split(sc.Text(), ",")
		out = append(out, User{Name: fields[0], Email: fields[1]})
	}
	return out, nil
}
