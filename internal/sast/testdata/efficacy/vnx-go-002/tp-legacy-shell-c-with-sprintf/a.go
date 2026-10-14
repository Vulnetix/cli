package a

func f(h string) {
~>	exec.Command("sh", "-c", fmt.Sprintf("ping %s", h))
~>	exec.Command("bash", "-c", "ping "+h)
~>	exec.Command(fmt.Sprintf("/bin/%s", h))
}
