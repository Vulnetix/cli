package a

func f(v string) {
	exec.Command("git", "rev-parse", "--verify", v+"^{commit}").Run()
	exec.Command("gh", "api", "advisories?cve_id="+cve+"&per_page=20").Output()
}
