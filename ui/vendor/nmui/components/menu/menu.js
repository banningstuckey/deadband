/* GENERATED for Deadband from nmui — do not hand-edit.
   The CSS-module import header of the original is removed:
   WebKit (Tauri's macOS/Linux webview) cannot parse it.
   This component's CSS is loaded by ui/index.html instead.
   Regenerate with tools/vendor_nmui.py. */

// Typeahead: index of the next label starting with the typed
// buffer, searching from just after `from` and wrapping. A
// buffer of one repeated letter ("ccc") cycles through that
// letter's items. -1 when nothing matches.
function nextTypeahead(labels, buffer, from) {
  let b = buffer.toLowerCase();
  if (b.length > 1 && [...b].every((c) => c === b[0])) b = b[0];
  for (let step = 1; step <= labels.length; step++) {
    const i = (from + step) % labels.length;
    if (labels[i].toLowerCase().startsWith(b)) return i;
  }
  return -1;
}

/**
 * <nmui-menu> — M3 menu. A popup list anchored to another
 * element; menus appear in front of everything else and close
 * on selection, Escape, or an outside press.
 *
 *   <nmui-button id="more" tonal>Open menu</nmui-button>
 *   <nmui-menu anchor="more">
 *     <button value="cut"><icon>content_cut</icon>Cut</button>
 *     <button value="copy"><icon>content_copy</icon>Copy</button>
 *     <nmui-divider></nmui-divider>
 *     <button value="paste">Paste</button>
 *   </nmui-menu>
 *
 * Items are native <button> children. A button can carry a
 * leading <icon>, a <small> supporting line under its label,
 * and a trailing <span trailing>⌘V</span>. A <button disabled>
 * is converted to aria-disabled on connect — per the menu
 * accessibility spec, a disabled item can still receive focus,
 * it just can't be selected.
 *
 * Variants: bare is the baseline menu (112–280dp wide, 4dp
 * corners, surface-container). [vertical] is the M3 Expressive
 * vertical menu: rounded container, inset pill items, tertiary
 * selected state, and <section title="…"> groups separated by
 * gaps. [vibrant] is the vertical menu in the tertiary color
 * mapping (implies the vertical geometry); use it sparingly.
 *
 * Selection: an item authored with [selected] makes the menu a
 * single-select menu — picking an item moves [selected] (and
 * its check mark) and closes. [multiple] menus toggle items
 * and stay open. Either way "change" fires with
 * { value, selected, item, menu }; plain action menus report
 * selected as undefined. "open" / "close" fire with { menu }.
 *
 * Submenus: a <nmui-menu> placed directly after an item button
 * becomes that item's submenu — the item gains a trailing
 * arrow and opens it on click, ArrowRight, or hover.
 *
 * Toggle with the [open] attribute or show()/close()/toggle().
 * The anchor gets aria-haspopup="menu" and a synced
 * aria-expanded; ArrowDown/ArrowUp on the anchor open the menu.
 * Keyboard inside: arrows move (disabled items included),
 * Home/End jump, letters typeahead, Escape closes the
 * innermost menu, Tab closes and moves on.
 *
 * Context menus: a menu with no anchor can be opened at a
 * pointer position with showAt(x, y) — wire it to a
 * contextmenu handler and preventDefault the native menu.
 */
class NMUIMenu extends HTMLElement {
  #ready = false;
  #point = null; // {x, y} for context menus (showAt), else null
  #wantFocus = null; // "first" | "last" | null, consumed on open
  #typeBuffer = "";
  #typeTimer = 0;
  #subOpenTimer = 0;
  #subCloseTimer = 0;
  #hoverBtn = null;

  #onDocDown = (e) => {
    if (!this.hasAttribute("open")) return;
    if (this.contains(e.target)) return;
    if (this.#anchor()?.contains(e.target)) return;
    this.#root().close();
  };

  #onScroll = (e) => {
    if (!this.hasAttribute("open")) return;
    if (e.target instanceof Node && this.contains(e.target)) return;
    this.#root().close();
  };

  #onAnchorKey = (e) => {
    if (this.hasAttribute("open")) return;
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    this.show(e.key === "ArrowDown" ? "first" : "last");
  };

  connectedCallback() {
    if (!this.#ready) {
      this.#ready = true;
      if (!this.hasAttribute("role")) this.setAttribute("role", "menu");
      this.#decorate();
      new MutationObserver(() => this.#decorate()).observe(this, {
        childList: true,
      });
      new MutationObserver(() => {
        if (this.hasAttribute("open")) this.#opened();
        else this.#closed();
      }).observe(this, { attributes: true, attributeFilter: ["open"] });

      this.addEventListener("click", (e) => this.#onClick(e));
      this.addEventListener("keydown", (e) => this.#onKey(e));
      this.addEventListener("pointerover", (e) => this.#onHover(e));

      const anchor = this.#anchor();
      if (anchor) {
        anchor.setAttribute("aria-haspopup", "menu");
        anchor.setAttribute(
          "aria-expanded",
          this.hasAttribute("open") ? "true" : "false"
        );
        anchor.addEventListener("keydown", this.#onAnchorKey);
      }
      if (this.hasAttribute("open")) this.#opened();
    }
    document.addEventListener("pointerdown", this.#onDocDown);
    window.addEventListener("scroll", this.#onScroll, true);
    window.addEventListener("resize", this.#onScroll);
  }

  disconnectedCallback() {
    document.removeEventListener("pointerdown", this.#onDocDown);
    window.removeEventListener("scroll", this.#onScroll, true);
    window.removeEventListener("resize", this.#onScroll);
  }

  // ---- structure ------------------------------------------------

  #anchor() {
    const id = this.getAttribute("anchor");
    return id ? document.getElementById(id) : null;
  }

  #root() {
    let m = this;
    while (m.#parentMenu()) m = m.#parentMenu();
    return m;
  }

  // Submenu linkage is DERIVED from the DOM, never stored: a
  // submenu is a direct child of its parent menu, sitting
  // directly after its parent item. Stored properties were
  // wiped when a submenu element finished upgrading after its
  // parent's first decorate pass — the class field
  // initializers overwrote them with null, leaving a parent
  // item that looked linked (arrow drawn) but acted like a
  // leaf (hover dead, click fired change and closed the menu).
  #parentMenu() {
    const p = this.parentElement;
    return p?.tagName === "NMUI-MENU" ? p : null;
  }

  #parentItem() {
    if (!this.#parentMenu()) return null;
    const prev = this.previousElementSibling;
    return prev?.tagName === "BUTTON" ? prev : null;
  }

  // This menu's own items — buttons whose nearest menu is this
  // one (submenu items belong to the submenu).
  #items() {
    return [...this.querySelectorAll("button")].filter(
      (b) => b.closest("nmui-menu") === this
    );
  }

  #submenus() {
    return [...this.querySelectorAll("nmui-menu")].filter(
      (m) => m.#parentMenu() === this
    );
  }

  #decorate() {
    for (const btn of this.#items()) {
      // Disabled items stay focusable (accessibility spec):
      // swap the native disabled for aria-disabled.
      if (btn.hasAttribute("disabled")) {
        btn.removeAttribute("disabled");
        btn.setAttribute("aria-disabled", "true");
      }
      if (btn.getAttribute("aria-disabled") === "true") {
        btn.setAttribute("tabindex", "-1");
      }
      // Wrap the label (text nodes + supporting <small>) so
      // icons and trailing content sit on the row's axis.
      if (!btn.querySelector(":scope > span.label")) {
        const label = document.createElement("span");
        label.className = "label";
        for (const node of [...btn.childNodes]) {
          if (node.nodeType === 3 || node.tagName === "SMALL") {
            label.append(node);
          }
        }
        const firstIcon = btn.querySelector(":scope > icon");
        firstIcon ? firstIcon.after(label) : btn.prepend(label);
      }
      btn.setAttribute("tabindex", "-1");
      // A menu directly after the item = its submenu.
      const sib = btn.nextElementSibling;
      if (sib?.tagName === "NMUI-MENU") {
        btn.setAttribute("aria-haspopup", "true");
        if (!btn.hasAttribute("aria-expanded")) {
          btn.setAttribute("aria-expanded", "false");
        }
        if (!btn.querySelector(":scope > icon.sub-arrow")) {
          const arrow = document.createElement("icon");
          arrow.className = "sub-arrow";
          arrow.setAttribute("aria-hidden", "true");
          arrow.textContent = "arrow_right";
          btn.append(arrow);
        }
      }
      this.#syncCheck(btn);
    }
    this.#syncRoles();
  }

  #mode() {
    if (this.hasAttribute("multiple")) return "checkbox";
    if (this.#items().some((b) => b.hasAttribute("selected"))) return "radio";
    return "menu";
  }

  #syncRoles() {
    const mode = this.#mode();
    for (const btn of this.#items()) {
      btn.setAttribute(
        "role",
        mode === "menu" ? "menuitem" : `menuitem${mode}`
      );
      if (mode === "menu") btn.removeAttribute("aria-checked");
      else {
        btn.setAttribute(
          "aria-checked",
          btn.hasAttribute("selected") ? "true" : "false"
        );
      }
    }
  }

  #syncCheck(btn) {
    const has = !!btn.querySelector(":scope > icon.check");
    if (btn.hasAttribute("selected") && !has) {
      const check = document.createElement("icon");
      check.className = "check";
      check.setAttribute("aria-hidden", "true");
      check.textContent = "check";
      btn.prepend(check);
    } else if (!btn.hasAttribute("selected") && has) {
      btn.querySelector(":scope > icon.check").remove();
    }
  }

  // ---- open / close ----------------------------------------------

  #opened() {
    this.#place();
    const anchor = this.#anchor();
    if (anchor) anchor.setAttribute("aria-expanded", "true");
    const pi = this.#parentItem();
    if (pi) pi.setAttribute("aria-expanded", "true");
    this.dispatchEvent(
      new CustomEvent("open", {
        detail: { menu: this },
        bubbles: true,
        composed: true,
      })
    );
    if (this.#wantFocus) {
      const items = this.#items();
      const target =
        this.#wantFocus === "last" ? items[items.length - 1] : items[0];
      this.#wantFocus = null;
      target?.focus();
    }
  }

  #closed() {
    this.#point = null;
    this.#hoverBtn = null;
    // A closing submenu re-arms its parent item's hover, so
    // hovering the same item again reopens it.
    const pm = this.#parentMenu();
    if (pm) pm.#hoverBtn = null;
    for (const sub of this.#submenus()) {
      if (sub.hasAttribute("open")) sub.close();
    }
    const anchor = this.#anchor();
    if (anchor) anchor.setAttribute("aria-expanded", "false");
    const pi = this.#parentItem();
    if (pi) pi.setAttribute("aria-expanded", "false");
    this.dispatchEvent(
      new CustomEvent("close", {
        detail: { menu: this },
        bubbles: true,
        composed: true,
      })
    );
    if (this.contains(document.activeElement)) {
      (this.#parentItem() ?? this.#anchor())?.focus();
    }
  }

  #place() {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const w = this.offsetWidth;
    const h = this.offsetHeight;
    let left;
    let top;
    let origin = "top left";
    if (this.#point) {
      // Context menu: open at the pointer, shifted back inside
      // the window when it would overflow an edge.
      const { x, y } = this.#point;
      left = Math.max(8, Math.min(x, vw - w - 8));
      top = Math.max(8, Math.min(y, vh - h - 8));
      origin = `${y + h > vh - 8 ? "bottom" : "top"} ${
        x + w > vw - 8 ? "right" : "left"
      }`;
    } else if (this.#parentMenu() && this.#parentItem()) {
      const pr = this.#parentMenu().getBoundingClientRect();
      const ir = this.#parentItem().getBoundingClientRect();
      const padTop =
        parseFloat(getComputedStyle(this.#parentMenu()).paddingTop) || 0;
      left = pr.right + 4;
      if (left + w > vw - 8) {
        left = pr.left - w - 4;
        origin = "top right";
      }
      top = ir.top - padTop;
      if (top + h > vh - 8) top = Math.max(8, vh - h - 8);
    } else {
      const anchor = this.#anchor();
      if (!anchor) return;
      const r = anchor.getBoundingClientRect();
      const rtl = getComputedStyle(this).direction === "rtl";
      left = rtl ? r.right - w : r.left;
      if (left + w > vw - 8) left = Math.max(8, vw - w - 8);
      if (left < 8) left = 8;
      top = r.bottom + 4;
      if (top + h > vh - 8) {
        top = r.top - h - 4;
        origin = origin.replace("top", "bottom");
      }
    }
    this.style.left = `${left}px`;
    this.style.top = `${top}px`;
    this.style.transformOrigin = origin;
  }

  show(focus = "first") {
    this.#point = null;
    if (this.hasAttribute("open")) return;
    this.#wantFocus = focus;
    this.setAttribute("open", "");
  }

  // Open at a viewport position (context menus). Re-calling it
  // while open moves the menu to the new point.
  showAt(x, y) {
    this.#point = { x, y };
    this.#wantFocus = "first";
    if (this.hasAttribute("open")) this.#place();
    else this.setAttribute("open", "");
  }

  close() {
    this.removeAttribute("open");
  }

  toggle() {
    this.hasAttribute("open") ? this.close() : this.show();
  }

  // ---- interaction -------------------------------------------------

  #value(btn) {
    return btn.getAttribute("value") ?? btn.textContent.trim();
  }

  #fireChange(btn, selected) {
    this.dispatchEvent(
      new CustomEvent("change", {
        detail: { value: this.#value(btn), selected, item: btn, menu: this },
        bubbles: true,
        composed: true,
      })
    );
  }

  #submenuOf(btn) {
    return this.#submenus().find((m) => m.#parentItem() === btn) ?? null;
  }

  #activate(btn) {
    if (btn.getAttribute("aria-disabled") === "true") return;
    const sub = this.#submenuOf(btn);
    if (sub) {
      sub.hasAttribute("open") ? sub.close() : sub.show();
      return;
    }
    const mode = this.#mode();
    if (mode === "checkbox") {
      const now = !btn.hasAttribute("selected");
      btn.toggleAttribute("selected", now);
      this.#syncCheck(btn);
      this.#syncRoles();
      this.#fireChange(btn, now);
      btn.focus();
      return;
    }
    if (mode === "radio") {
      for (const other of this.#items()) {
        if (other !== btn && other.hasAttribute("selected")) {
          other.removeAttribute("selected");
          this.#syncCheck(other);
        }
      }
      btn.setAttribute("selected", "");
      this.#syncCheck(btn);
      this.#syncRoles();
      this.#fireChange(btn, true);
      this.#root().close();
      return;
    }
    this.#fireChange(btn, undefined);
    this.#root().close();
  }

  #onClick(e) {
    const btn =
      e.target instanceof Element ? e.target.closest("button") : null;
    if (!btn || btn.closest("nmui-menu") !== this) return;
    this.#activate(btn);
  }

  #focusItem(btn) {
    btn?.focus();
  }

  #move(delta) {
    const items = this.#items();
    if (!items.length) return;
    const i = items.indexOf(document.activeElement);
    const next =
      items[(i + delta + items.length) % items.length] ?? items[0];
    this.#focusItem(next);
  }

  #onKey(e) {
    if (!this.hasAttribute("open")) return;
    const btn =
      e.target instanceof Element ? e.target.closest("button") : null;
    if (btn && btn.closest("nmui-menu") !== this) return; // a submenu's key

    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      if (this.#parentMenu()) {
        const item = this.#parentItem();
        this.close();
        item?.focus();
      } else {
        this.close();
      }
      return;
    }
    if (e.key === "Tab") {
      this.#root().close();
      return;
    }
    if (!btn) return;

    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        this.#move(1);
        break;
      case "ArrowUp":
        e.preventDefault();
        this.#move(-1);
        break;
      case "Home":
        e.preventDefault();
        this.#focusItem(this.#items()[0]);
        break;
      case "End":
        e.preventDefault();
        this.#focusItem(this.#items().at(-1));
        break;
      case "ArrowRight": {
        const sub = this.#submenuOf(btn);
        if (sub) {
          e.preventDefault();
          sub.show();
        }
        break;
      }
      case "ArrowLeft":
        if (this.#parentMenu()) {
          e.preventDefault();
          const item = this.#parentItem();
          this.close();
          item?.focus();
        } else {
          const sub = this.#submenuOf(btn);
          if (sub?.hasAttribute("open")) {
            e.preventDefault();
            sub.close();
          }
        }
        break;
      default:
        if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
          this.#typeBuffer += e.key;
          clearTimeout(this.#typeTimer);
          this.#typeTimer = setTimeout(() => (this.#typeBuffer = ""), 500);
          const items = this.#items();
          const labels = items.map((b) => b.textContent.trim());
          const hit = nextTypeahead(
            labels,
            this.#typeBuffer,
            items.indexOf(document.activeElement)
          );
          if (hit >= 0) {
            e.preventDefault();
            this.#focusItem(items[hit]);
          }
        }
    }
  }

  // Hover intent for submenus: a short delay before opening so
  // diagonal pointer travel doesn't flicker menus, and a grace
  // delay before an open submenu closes.
  #onHover(e) {
    const btn =
      e.target instanceof Element ? e.target.closest("button") : null;
    if (!btn) return;
    if (btn.closest("nmui-menu") !== this) {
      // The pointer is inside one of my submenus — keep it open.
      clearTimeout(this.#subCloseTimer);
      return;
    }
    // pointerover refires on every child boundary inside the
    // item (icon, label span) — without this guard, ordinary
    // micro-movement kept restarting the intent timer and the
    // submenu never opened.
    if (btn === this.#hoverBtn) return;
    this.#hoverBtn = btn;
    clearTimeout(this.#subOpenTimer);
    const sub = this.#submenuOf(btn);
    if (sub) {
      this.#subOpenTimer = setTimeout(() => sub.show(null), 250);
    } else {
      clearTimeout(this.#subCloseTimer);
      this.#subCloseTimer = setTimeout(() => {
        for (const open of this.#submenus()) {
          if (open.hasAttribute("open")) open.close();
        }
      }, 300);
    }
  }
}

if (!customElements.get("nmui-menu")) {
  customElements.define("nmui-menu", NMUIMenu);
}

export { NMUIMenu };
