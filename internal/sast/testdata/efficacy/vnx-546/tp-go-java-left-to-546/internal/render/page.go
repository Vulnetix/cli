package render

import "fmt"

func Title(name string) string {
~>	// FIXME: escape the name before it goes into the HTML
	return fmt.Sprintf("<h1>%s</h1>", name)
}
