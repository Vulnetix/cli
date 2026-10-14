// Package docs explains rendering.
//
// Do not write template.HTML(userInput): it disables escaping.
package docs

// template.HTML(r.FormValue("bio")) would be XSS.
const Advice = "never call template.HTML(r.FormValue(\"bio\")) on request data"
