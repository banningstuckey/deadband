/* GENERATED for Deadband from nmui — do not hand-edit.
   The CSS-module import header of the original is removed:
   WebKit (Tauri's macOS/Linux webview) cannot parse it.
   This component's CSS is loaded by ui/index.html instead.
   Regenerate with tools/vendor_nmui.py. */

/**
 * <nmui-tabs> — M3 tabs. Decorates <a> / <button> children
 * as an ARIA tablist: roving tabindex, arrow keys move and
 * activate, Home/End jump, and an animated indicator tracks
 * the selected tab.
 *
 *   <nmui-tabs>
 *     <button selected><icon>flight</icon>Flights</button>
 *     <button><icon>luggage</icon>Trips</button>
 *   </nmui-tabs>
 *
 * Bare = primary tabs (icon + label stack, 64dp; label-only
 * 48dp). [secondary] = secondary tabs (label only, on-surface
 * when active, full-width 2dp indicator). Primary indicators
 * hug the tab's content (min 24dp); secondary span the tab.
 *
 * [scrollable] sizes tabs to their labels and scrolls the
 * row instead of dividing it into equal sections.
 * An <nmui-badge> inside a tab rides along (inline after
 * the label, or overlapping the stacked icon).
 * A disabled tab (disabled button, or [disabled] on an
 * anchor) is skipped by arrows and can't be selected.
 *
 * Panels: give a tab controls="<panel-id>" and that element
 * becomes its tabpanel — the component wires aria-controls /
 * aria-labelledby and shows only the selected tab's panel.
 * Without controls, tabs are selection-only (navigation).
 *
 * Emits "change" with { value, tab, tabs } on selection
 * (not on the initial selection). value = the tab's value
 * attribute or its text.
 */
let uid = 0;

// The tab's label text: the content wrap's text, minus the
// icon ligature and any badge (the badge lives outside the
// wrap; the icon is inside it).
function labelText(tab) {
  const content = tab.querySelector(":scope > content");
  if (!content) return tab.textContent.trim();
  return [...content.childNodes]
    .filter((n) => n.nodeType === 3 || (n instanceof Element && n.tagName !== "ICON"))
    .map((n) => n.textContent)
    .join("")
    .trim();
}

class NMUITabs extends HTMLElement {
  #ready = false;
  #indicator = null;
  #tabs = [];

  connectedCallback() {
    if (this.#ready) return;
    this.#ready = true;

    if (!this.hasAttribute("role")) this.setAttribute("role", "tablist");

    this.#indicator = document.createElement("indicator");
    this.appendChild(this.#indicator);

    this.#tabs = [...this.querySelectorAll(":scope > a, :scope > button")];
    let stacked = false;
    for (const tab of this.#tabs) {
      tab.setAttribute("role", "tab");
      if (tab.tagName === "BUTTON" && !tab.hasAttribute("type")) {
        tab.setAttribute("type", "button");
      }
      if (!tab.id) tab.id = `nmui-tab-${++uid}`;
      // Wrap the tab's content (icon + label) so the primary
      // indicator can hug it; a badge stays outside the wrap.
      const badge = tab.querySelector(":scope > nmui-badge");
      const content = document.createElement("content");
      let node = tab.firstChild;
      while (node) {
        const next = node.nextSibling;
        if (node !== badge) content.appendChild(node);
        node = next;
      }
      tab.prepend(content);
      if (content.querySelector("icon")) stacked = true;
      if (this.#disabled(tab)) {
        tab.setAttribute("aria-disabled", "true");
        tab.removeAttribute("disabled");
      }
      const panelId = tab.getAttribute("controls");
      if (panelId) {
        tab.setAttribute("aria-controls", panelId);
        const panel = document.getElementById(panelId);
        if (panel) {
          panel.setAttribute("role", "tabpanel");
          panel.setAttribute("aria-labelledby", tab.id);
        }
      }
      tab.addEventListener("click", (e) => {
        if (this.#disabled(tab)) {
          e.preventDefault();
          return;
        }
        this.#select(tab, true);
      });
      tab.addEventListener("pointerdown", (e) => {
        if (!this.#disabled(tab)) this.#ripple(tab, e);
      });
      // External [selected] changes re-sync silently.
      new MutationObserver(() => {
        if (tab.hasAttribute("selected") && this.#current() !== tab) {
          this.#select(tab, false);
        }
      }).observe(tab, { attributes: true, attributeFilter: ["selected"] });
    }
    if (stacked && !this.hasAttribute("secondary")) {
      this.setAttribute("stacked", "");
    }

    this.addEventListener("keydown", (e) => {
      const tab = e.target.closest?.("[role=tab]");
      if (!tab || !this.#tabs.includes(tab)) return;
      const enabled = this.#tabs.filter((t) => !this.#disabled(t));
      const i = enabled.indexOf(tab);
      let next = null;
      if (e.key === "ArrowRight") next = enabled[(i + 1) % enabled.length];
      else if (e.key === "ArrowLeft") next = enabled[(i - 1 + enabled.length) % enabled.length];
      else if (e.key === "Home") next = enabled[0];
      else if (e.key === "End") next = enabled[enabled.length - 1];
      if (next) {
        e.preventDefault();
        next.focus();
        this.#select(next, true);
      }
    });

    const initial =
      this.#tabs.find((t) => t.hasAttribute("selected") && !this.#disabled(t)) ||
      this.#tabs.find((t) => !this.#disabled(t));
    if (initial) this.#select(initial, false);
    requestAnimationFrame(() => this.#move());

    if (typeof ResizeObserver !== "undefined") {
      new ResizeObserver(() => this.#move()).observe(this);
    } else {
      window.addEventListener("resize", () => this.#move());
    }
  }

  #disabled(tab) {
    return tab.hasAttribute("disabled") || tab.getAttribute("aria-disabled") === "true";
  }

  #current() {
    return this.#tabs.find((t) => t.hasAttribute("selected")) || null;
  }

  #select(tab, emit) {
    for (const t of this.#tabs) {
      const on = t === tab;
      t.toggleAttribute("selected", on);
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      const panelId = t.getAttribute("controls");
      if (panelId) {
        const panel = document.getElementById(panelId);
        if (panel) panel.hidden = !on;
      }
    }
    this.#move();
    if (emit) {
      this.dispatchEvent(
        new CustomEvent("change", {
          detail: {
            value: tab.getAttribute("value") ?? labelText(tab),
            tab,
            tabs: this,
          },
          bubbles: true,
          composed: true,
        })
      );
    }
  }

  // The indicator positions from layout offsets (immune to
  // the row's own horizontal scrolling). Primary: hug the
  // content, inset 2dp a side, min 24dp. Secondary: the
  // tab's full width.
  #move() {
    const tab = this.#current();
    if (!tab || !this.#indicator) return;
    let left = tab.offsetLeft;
    let width = tab.offsetWidth;
    if (!this.hasAttribute("secondary")) {
      const content = tab.querySelector(":scope > content");
      if (content) {
        const cw = content.offsetWidth;
        width = Math.max(24, cw - 4);
        left = tab.offsetLeft + (tab.offsetWidth - width) / 2;
      }
    }
    this.#indicator.style.transform = `translateX(${left}px)`;
    this.#indicator.style.width = `${width}px`;
  }

  // Press ripple, the button component's technique: a
  // currentColor disc scaled up with WAAPI, then removed.
  #ripple(tab, e) {
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
    const r = tab.getBoundingClientRect();
    const d = Math.max(r.width, r.height) * 2;
    const disc = document.createElement("ripple");
    disc.style.width = disc.style.height = `${d}px`;
    disc.style.left = `${(e.clientX || r.left + r.width / 2) - r.left - d / 2}px`;
    disc.style.top = `${(e.clientY || r.top + r.height / 2) - r.top - d / 2}px`;
    tab.appendChild(disc);
    const anim = disc.animate(
      [
        { transform: "scale(0)", opacity: 0.12 },
        { transform: "scale(1)", opacity: 0 },
      ],
      { duration: 450, easing: "cubic-bezier(0.2, 0, 0, 1)" }
    );
    anim.onfinish = () => disc.remove();
  }
}

if (!customElements.get("nmui-tabs")) {
  customElements.define("nmui-tabs", NMUITabs);
}

export { NMUITabs };
