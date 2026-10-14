package a

func f(owner, repo string) {
	cmd := exec.Command("gh", "api", fmt.Sprintf("repos/%s/%s", owner, repo), "--jq", ".x")
}
