package main

func gen(b *strings.Builder, t T) {
	fmt.Fprintf(b, "{{< callout type=\"warning\" >}}\n%s\n{{< /callout >}}\n", t.Note)
	fmt.Fprintf(&b, "| <a id=%q></a>%s |\n", id, name)
}
