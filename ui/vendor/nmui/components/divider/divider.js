/* GENERATED for Deadband from nmui — do not hand-edit.
   The CSS-module import header of the original is removed:
   WebKit (Tauri's macOS/Linux webview) cannot parse it.
   This component's CSS is loaded by ui/index.html instead.
   Regenerate with tools/vendor_nmui.py. */

/**
 * <nmui-divider> — M3 divider. A thin rule that groups content.
 * Decorative: it fires no events and takes no content.
 *
 *   <nmui-divider>                    full width
 *   <nmui-divider inset>              16dp in from the leading edge
 *   <nmui-divider middle-inset>       16dp in from both edges
 *   <nmui-divider vertical>           for row layouts; combines
 *                                     with [inset] / [middle-inset]
 *
 * The element carries role="separator" (the native <hr> pattern);
 * a [vertical] divider also gets aria-orientation="vertical",
 * kept in sync if the attribute changes after connect.
 */
class NMUIDivider extends HTMLElement {
  static observedAttributes = ["vertical"];

  connectedCallback() {
    if (!this.hasAttribute("role")) this.setAttribute("role", "separator");
    this.#syncOrientation();
  }

  attributeChangedCallback() {
    this.#syncOrientation();
  }

  #syncOrientation() {
    if (this.hasAttribute("vertical")) {
      this.setAttribute("aria-orientation", "vertical");
    } else {
      this.removeAttribute("aria-orientation");
    }
  }
}

if (!customElements.get("nmui-divider")) {
  customElements.define("nmui-divider", NMUIDivider);
}

export { NMUIDivider };
