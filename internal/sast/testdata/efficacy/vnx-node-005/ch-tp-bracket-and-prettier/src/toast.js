export function toast(node, msg, detailsHtml) {
~>  node["innerHTML"] = msg;
~>  node.insertAdjacentHTML(
    "afterbegin",
    `<details><summary>More</summary>${detailsHtml}</details>`,
  );
}
