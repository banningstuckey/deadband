import badgeStyles from "./badge.css" with { type: "css" };

if (!document.adoptedStyleSheets.includes(badgeStyles)) {
  document.adoptedStyleSheets.push(badgeStyles);
}

/**
 * <nmui-badge> — M3 badge. A small count or status mark anchored
 * to its parent. Wraps the anchor; the host's own text becomes
 * the badge label.
 *
 * No size attribute — size follows content, as in M3. Empty
 * content renders the small badge, a 6dp dot tucked into the
 * anchor's top-trailing corner. Text renders the large badge,
 * 16dp tall with a label-small count, straddling that corner
 * (bottom 14 below the anchor's top edge, leading edge 12
 * leading of its trailing edge). Cap the label at four
 * characters including "+" ("999+").
 *
 *   <nmui-badge><nmui-button icon>notifications</nmui-button></nmui-badge>
 *   <nmui-badge>99+<nmui-button icon>mail</nmui-button></nmui-badge>
 *
 * Colors are error / on-error. The anchor is the wrapped
 * element's box, so on an icon button the corner is the
 * button's corner, not the glyph's.
 */
class NMUIBadge extends HTMLElement {
  #ready = false;

  // The label after connection lives in the <dot> the component
  // creates — setting the host's textContent would replace the
  // anchor too. label is the safe way to change the count in code:
  //   badge.label = "5";   // "" renders the small dot badge
  get label() {
    return this.querySelector(":scope > dot")?.textContent ?? "";
  }

  set label(v) {
    const dot = this.querySelector(":scope > dot");
    if (dot) dot.textContent = v == null ? "" : String(v);
  }

  connectedCallback() {
    if (this.#ready) return;
    this.#ready = true;

    // Move the host's own text into the badge dot; element children stay
    // in flow as the anchor.
    const dot = document.createElement("dot");
    const text = [];
    [...this.childNodes].forEach((n) => {
      if (n.nodeType === Node.TEXT_NODE) {
        if (n.textContent.trim()) text.push(n.textContent.trim());
        n.remove();
      }
    });
    dot.textContent = text.join(" ");
    this.prepend(dot);
  }
}

if (!customElements.get("nmui-badge")) {
  customElements.define("nmui-badge", NMUIBadge);
}

export { NMUIBadge };
