import cardStyles from "./card.css" with { type: "css" };

if (!document.adoptedStyleSheets.includes(cardStyles)) {
  document.adoptedStyleSheets.push(cardStyles);
}

/**
 * <nmui-card> — M3 card. Content is free light DOM — headline,
 * body, actions, media, whatever the card holds.
 *
 * Variants (pick one; bare is elevated): [elevated] [filled]
 * [outlined]. Elevated = surface-container-low at level 1
 * (level 2 on hover); filled = surface-container-highest at
 * level 0 (level 1 on hover); outlined = surface with an
 * outline-variant border at level 0 (level 1 on hover). Shape
 * is a 12dp radius, padding 16dp.
 *
 * [href] makes the whole card clickable (keyboard-operable:
 * Enter/Space activate it) and [disabled] fades it and unwires
 * it. Pressed tints the container 12% toward on-surface (the
 * M3 pressed state-layer opacity); focus shows an outline.
 * Hover, pressed, and ripple belong to directly actionable
 * ([href]) cards only — a non-actionable card has no hover
 * state. [dragging] lifts the card to level 3; dragging itself
 * is app behavior (see the docs demo), the card only owns the
 * look.
 *
 *   <nmui-card outlined>
 *     <headline small>Title</headline>
 *     <p>Body copy.</p>
 *   </nmui-card>
 */
class NMUICard extends HTMLElement {
  #ready = false;
  #rippleTimer = null;

  // Press feedback for directly actionable cards: ::after expands
  // from the press point and fades (same mechanism as the button
  // ripple; currentColor here is on-surface). The attribute is
  // re-set per press so rapid presses restart the animation.
  #ripple(x, y) {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const rect = this.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const size = Math.max(rect.width, rect.height) * 2.2;
    this.style.setProperty("--ripple-x", `${x - rect.left}px`);
    this.style.setProperty("--ripple-y", `${y - rect.top}px`);
    this.style.setProperty("--ripple-size", `${size}px`);
    this.removeAttribute("rippling");
    void this.offsetWidth;
    this.setAttribute("rippling", "");
    clearTimeout(this.#rippleTimer);
    this.#rippleTimer = setTimeout(() => this.removeAttribute("rippling"), 500);
  }

  connectedCallback() {
    if (this.#ready) return;
    this.#ready = true;
    if (this.hasAttribute("disabled")) {
      this.setAttribute("aria-disabled", "true");
      return;
    }
    if (this.hasAttribute("href")) {
      if (!this.hasAttribute("tabindex")) this.setAttribute("tabindex", "0");
      if (!this.hasAttribute("role")) this.setAttribute("role", "link");
    }
    // Listeners are attached unconditionally and check [href] at
    // event time, so adding or changing href in code — the native
    // way, as on an <a> — makes the card clickable without a
    // rebuild, and an author-set tabindex no longer unwires it.
    this.addEventListener("click", () => {
      if (this.hasAttribute("disabled") || !this.hasAttribute("href")) return;
      window.location = this.getAttribute("href");
    });
    this.addEventListener("pointerdown", (e) => {
      if (this.hasAttribute("disabled") || !this.hasAttribute("href")) return;
      this.#ripple(e.clientX, e.clientY);
    });
    this.addEventListener("keydown", (e) => {
      if (this.hasAttribute("disabled") || !this.hasAttribute("href")) return;
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        if (!e.repeat) {
          const r = this.getBoundingClientRect();
          this.#ripple(r.left + r.width / 2, r.top + r.height / 2);
        }
        this.click();
      }
    });
  }
}

if (!customElements.get("nmui-card")) {
  customElements.define("nmui-card", NMUICard);
}

export { NMUICard };
