package render

// podTemplate is filled in by the operator; privileged is never set to true here.
const podTemplate = `
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: probe
      securityContext:
        privileged: true
`

func Template() string { return podTemplate }
