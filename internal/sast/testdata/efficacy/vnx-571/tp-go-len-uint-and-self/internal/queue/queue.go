package queue

type Item struct {
	Priority int
}

func Pop(items []Item, want uint32) (Item, bool) {
~>	if len(items) >= 0 {
		_ = items
	}
~>	if want >= 0 {
		return items[want], true
	}
	return Item{}, false
}

func Less(a, b Item) bool {
~>	if a.Priority == a.Priority {
		return false
	}
	return a.Priority < b.Priority
}
