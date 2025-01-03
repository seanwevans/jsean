function updateTableOfContents() {
  const toc = document.getElementById("toc");
  Array.from(toc.querySelectorAll("tr")).forEach(row => {
    const titleCell = row.children[0]; // First cell: Title        
    const pageCell = row.children[1]; // Second cell: Page number
    const rowWidth = row.offsetWidth;
    if (titleCell && pageCell) {
      const titleWidth = titleCell.offsetWidth;
      const pageWidth = pageCell.offsetWidth;
      const textlen = titleCell.innerText.length;
      let numDots = Math.floor(rowWidth / 9.25 - textlen);
      numDots = numDots >= 0 ? numDots : 0;
      row.children[0].innerHTML += " " + "·".repeat(numDots) + " ";
    }
  });
}

function boldText(element) {
  if (element.tagName === "TABLE" || element.closest("table")) return;
  element.childNodes.forEach(node => {
    if (node.nodeType === Node.TEXT_NODE) {
      const boldedText = node.nodeValue.replace(/(JSean)/g, "<strong>$1</strong>");
      const wrapper = document.createElement("span");
      wrapper.innerHTML = boldedText;
      node.replaceWith(wrapper);
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      boldText(node);
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  updateTableOfContents();
  boldText(document.body);
});
