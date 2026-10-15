package mail

func send() error {
~>	auth := smtp.PlainAuth("", "alerts@example.org", "Sm7p-Passw0rd", "smtp.example.org")
~>	req.SetBasicAuth("svc", "B4sic-Passw0rd")
~>	u := url.UserPassword("deploy", "D3ploy-Passw0rd")
	cfg := &ssh.ClientConfig{
		User: "deploy",
~>		Auth: []ssh.AuthMethod{ssh.Password("Ssh-Passw0rd")},
	}
	return nil
}
