// Sequences VNX-182 does not judge stay with this rule.
export function stripFrames(html) {
~>  return html.replace(/<iframe/g, '');
}

export function stripVb(url) {
~>  return url.replaceAll('vbscript:', '');
}

export function stripChain(cmd) {
~>  return cmd.replace('&&', '').replace('||', '');
}

export function stripSubshell(arg) {
~>  return arg.replace("$(", "");
}

export function stripKeyword(q) {
~>  return q.replace(/SELECT/g, '');
}

export function stripScript(html) {
  // a script tag is VNX-182's
  return html.replace('<script>', '');
}
