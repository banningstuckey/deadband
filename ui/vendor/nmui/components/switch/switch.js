/* GENERATED for Deadband from nmui — do not hand-edit.
   The CSS-module import header of the original is removed:
   WebKit (Tauri's macOS/Linux webview) cannot parse it.
   This component's CSS is loaded by ui/index.html instead.
   Regenerate with tools/vendor_nmui.py. */

/**
 * <nmui-switch> — M3 switch. Decorates a native checkbox
 * input (given role="switch"), so forms, validation, and
 * keyboard behavior come free. A switch takes effect
 * immediately — it's a setting, not a form answer.
 *
 *   <nmui-switch><input type="checkbox">Wi-Fi</nmui-switch>
 *   <nmui-switch><input type="checkbox" checked>Wi-Fi</nmui-switch>
 *
 * Spec geometry: track 52×32 with a 2dp outline (off only),
 * handle 16dp off / 24dp on / 28dp pressed, 40dp state
 * layer, 48dp target. Off: surface-container-highest track,
 * outline handle. On: primary track, on-primary handle.
 * Label text stays on-surface (38% when disabled).
 *
 * Icons (optional, 16dp in the handle): author an <icon>
 * for the off state and an <icon selected> for the on
 * state — either or both:
 *
 *   <nmui-switch>
 *     <input type="checkbox">
 *     <icon>close</icon><icon selected>check</icon>
 *     Dark theme
 *   </nmui-switch>
 *
 * With any icon the handle is 24dp in both states. Pick
 * glyphs that read as a binary (check / x), per the
 * guidelines — not decoration.
 *
 * Label text is wrapped in a native <label> at runtime, so
 * it is the input's accessible name and clicking it toggles
 * natively. Programmatic sets (input.checked = true) fire
 * no change event, so the input's own setters are reflected
 * to the host, like the other form controls.
 */
let uid = 0;

class NMUISwitch extends HTMLElement {
  #ready = false;
  #input = null;

  connectedCallback() {
    if (this.#ready) return;
    this.#ready = true;

    this.#input = this.querySelector(":scope > input[type=checkbox]");
    if (!this.#input) return;
    if (!this.#input.hasAttribute("role")) {
      this.#input.setAttribute("role", "switch");
    }

    // Icons first: they belong to the handle, not the label.
    const icons = [...this.querySelectorAll(":scope > icon")];
    const track = document.createElement("track");
    const handle = document.createElement("handle");
    for (const icon of icons) {
      icon.toggleAttribute("on", icon.hasAttribute("selected"));
      icon.removeAttribute("selected");
      handle.appendChild(icon);
    }
    if (icons.length) this.setAttribute("icons", "");
    track.appendChild(handle);
    this.prepend(track);

    // Label: wrap the remaining non-input content in a
    // native <label> tied to the input, unless the author
    // already provided one.
    if (!this.querySelector(":scope > label")) {
      const label = document.createElement("label");
      let node = this.firstChild;
      while (node) {
        const next = node.nextSibling;
        if (node !== this.#input && node !== track) label.appendChild(node);
        node = next;
      }
      if (label.childNodes.length) {
        if (!this.#input.id) this.#input.id = `nmui-sw-${++uid}`;
        label.htmlFor = this.#input.id;
        this.appendChild(label);
      }
    }

    const sync = () => {
      this.toggleAttribute("checked", this.#input.checked);
      this.toggleAttribute("disabled", this.#input.disabled);
    };
    this.#input.addEventListener("change", sync);
    new MutationObserver(sync).observe(this.#input, { attributes: true });

    // A form reset reverts the input with no change event —
    // re-sync just after it lands.
    if (this.#input.form) {
      this.#input.form.addEventListener("reset", () => setTimeout(sync, 0));
    }

    // Reflect programmatic property sets (see JSDoc).
    const proto = Object.getPrototypeOf(this.#input);
    for (const prop of ["checked", "disabled"]) {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || typeof desc.set !== "function") continue;
      Object.defineProperty(this.#input, prop, {
        get() {
          return desc.get.call(this);
        },
        set(v) {
          desc.set.call(this, v);
          sync();
        },
        configurable: true,
      });
    }
    sync();

    this.addEventListener("click", (e) => {
      if (this.#input.disabled) return;
      if (e.target === this.#input) return;
      if (e.target.closest?.("label")) return;
      e.preventDefault();
      this.#input.click();
    });
  }
}

if (!customElements.get("nmui-switch")) {
  customElements.define("nmui-switch", NMUISwitch);
}

export { NMUISwitch };
