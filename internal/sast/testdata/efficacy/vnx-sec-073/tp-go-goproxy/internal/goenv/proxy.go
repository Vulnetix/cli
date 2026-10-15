package goenv

~>const goProxy = "https://mirror:Gq7Lz2Xp9Rv@@@sample:p[r]ox[y][.]a[c]me[.]io[/]go[p]ro[x]y@@,direct"

func Env() []string { return []string{"GOPROXY=" + goProxy} }
