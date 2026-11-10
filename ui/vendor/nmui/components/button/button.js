import buttonStyles from "./button.css" with { type: "css" };

if (!document.adoptedStyleSheets.includes(buttonStyles)) {
  document.adoptedStyleSheets.push(buttonStyles);
}

const VARIANTS = ["elevated", "filled", "tonal", "outlined", "text"];
const SIZES = ["xsmall", "small", "medium", "large", "xlarge"];

/**
 * <nmui-button> — one tag, every button. Bare attributes declare the role
 * and the variants; the element enhances its light-DOM children.
 *
 * Roles (pick one):
 *   (default)       a button
 *   [toggle]        a toggle button — flips [selected] on click, synced
 *                   to aria-pressed. Combines with [icon].
 *   [icon]          an icon button — content becomes the icon
 *   [split]         a split button — two nmui-button children (action +
 *                   menu arrow). The host copies its variant/size to the
 *                   children; the arrow toggles [open] on the host.
 *   [group]         a button group — selects its nmui-button children
 *                   ([multiple] selects independently). The host's size
 *                   is copied to children that don't declare one.
 *   [fab]           a floating action button — content becomes the icon
 *   [fab][extended] an extended FAB — icon + label
 *   [fab][menu]     a FAB menu — nmui-button children become the menu
 *                   actions; the remaining content is the FAB's icon.
 *                   open()/close()/toggle() are public.
 *
 * Variants (pick one): [elevated] [filled] [tonal] [outlined] [text]
 *   Toggle colors follow the M3 table per variant (no toggle [text]).
 *   Icon buttons: [filled] (default) [tonal] [outlined] [standard]
 *   FABs: primary container (default), [secondary], [tertiary]
 * Sizes (pick one):    [xsmall] [small] [medium] [large] [xlarge]
 *   FAB sizes: [small] 40 · default 56 · [medium] 80 · [large] 96
 * Shape: [square] for the square family (default round — morphs on press;
 *   a selected toggle rests square, or round when [square])
 * State: [disabled] [selected] [unselected] [open] (split / fab menu)
 * Press feedback: every press ripples from the press point
 * (keyboard activation ripples from the center). Focus shows a
 * ring in the button's own content color on keyboard Tab only;
 * disabled buttons leave the tab order entirely.
 *
 * Emits a bubbling, composed "change" event. Leaf: { value, button }.
 * Toggles add { selected }; groups re-emit the picked child; split's
 * arrow and fab menu add { open }.
 *
 *   <nmui-button tonal large>Push me</nmui-button>
 *   <nmui-button toggle tonal>Wi-Fi</nmui-button>
 *   <nmui-button icon standard>keyboard_arrow_left</nmui-button>
 *   <nmui-button split tonal>
 *     <nmui-button>Send</nmui-button>
 *     <nmui-button icon>arrow_drop_down</nmui-button>
 *   </nmui-button>
 *   <nmui-button group connected>
 *     <nmui-button value="counts" selected>Counts</nmui-button>
 *     <nmui-button value="rates">Rates</nmui-button>
 *   </nmui-button>
 *   <nmui-button fab><icon>edit</icon></nmui-button>
 *   <nmui-button fab extended><icon>edit</icon>Compose</nmui-button>
 *   <nmui-button fab menu>
 *     <icon>add</icon>
 *     <nmui-button>New note</nmui-button>
 *     <nmui-button>New task</nmui-button>
 *   </nmui-button>
 */
class NMUIButton extends HTMLElement {
  #ready = false;
  #fabIcon = null;
  #fabIconText = "";

  get isGroup() {
    return this.hasAttribute("group");
  }

  get isSplit() {
    return this.hasAttribute("split");
  }

  get isFabMenu() {
    return this.hasAttribute("fab") && this.hasAttribute("menu");
  }

  get value() {
    return this.getAttribute("value");
  }

  // Property sets work the native way: they reflect to the
  // attribute (and the visuals/ARIA that key off it) and, like
  // native programmatic sets, fire no events. Use .click() when
  // you want the full press — toggle flip, change event and all.
  set value(v) {
    if (v == null) this.removeAttribute("value");
    else this.setAttribute("value", String(v));
  }

  get selected() {
    return this.hasAttribute("selected");
  }

  set selected(v) {
    this.#setSelected(Boolean(v));
  }

  get disabled() {
    return this.hasAttribute("disabled");
  }

  set disabled(v) {
    const on = Boolean(v);
    this.toggleAttribute("disabled", on);
    if (on) this.setAttribute("aria-disabled", "true");
    else this.removeAttribute("aria-disabled");
    if (this.hasAttribute("tabindex")) {
      this.setAttribute("tabindex", on ? "-1" : "0");
    }
  }

  connectedCallback() {
    if (this.#ready) return;
    this.#ready = true;

    if (this.isGroup) return this.#initGroup();
    if (this.isSplit) return this.#initSplit();
    if (this.isFabMenu) return this.#initFabMenu();

    this.#wrapContent();
    this.#initButton();
  }

  disconnectedCallback() {
    document.removeEventListener("pointerdown", this.#onOutside);
  }

  // -- shared ---------------------------------------------------------------

  #emit(detail) {
    this.dispatchEvent(
      new CustomEvent("change", { detail, bubbles: true, composed: true })
    );
  }

  #inGroup() {
    const p = this.parentElement;
    return p?.tagName === "NMUI-BUTTON" && p.hasAttribute("group");
  }

  #setSelected(on) {
    this.toggleAttribute("selected", on);
    this.toggleAttribute("unselected", !on);
    if (this.hasAttribute("toggle")) {
      this.setAttribute("aria-pressed", String(on));
    }
  }

  // Copies the host's variant/size to children that don't declare their own.
  #propagate(kids) {
    const variant = VARIANTS.find((v) => this.hasAttribute(v));
    const size = SIZES.find((s) => this.hasAttribute(s));
    kids.forEach((k) => {
      if (variant && !VARIANTS.some((v) => k.hasAttribute(v))) {
        k.setAttribute(variant, "");
      }
      if (size && !SIZES.some((s) => k.hasAttribute(s))) {
        k.setAttribute(size, "");
      }
    });
  }

  #wrapContent() {
    if (this.querySelector(":scope > container")) return;
    const container = document.createElement("container");
    // The fab menu's <menu> of actions is not trigger content.
    const nodes = [...this.childNodes].filter(
      (n) => !(n instanceof Element && n.tagName === "MENU")
    );
    const asIcon =
      this.hasAttribute("icon") ||
      (this.hasAttribute("fab") && !this.hasAttribute("extended"));
    if (asIcon) {
      // Authored <icon> elements are reused as-is, so their attributes
      // (e.g. [outline], [selected]) survive. One icon is the norm; two
      // make a toggle swap pair. Anything else is wrapped into one.
      const meaningful = nodes.filter(
        (n) => n instanceof Element || n.textContent.trim() !== ""
      );
      const authored = meaningful.filter((n) => n.tagName === "ICON");
      if (authored.length > 0 && authored.length === meaningful.length) {
        authored.forEach((icon) => container.appendChild(icon));
      } else {
        const icon = document.createElement("icon");
        nodes.forEach((n) => {
          if (n instanceof Element && n.tagName === "ICON") {
            while (n.firstChild) icon.appendChild(n.firstChild);
          } else {
            icon.appendChild(n);
          }
        });
        container.appendChild(icon);
      }
    } else {
      nodes.forEach((n) => container.appendChild(n));
    }
    this.prepend(container);
  }

  // -- ripple ---------------------------------------------------------------
  // Press feedback: a disc that expands from the press point and
  // fades. currentColor (via CSS) makes it the container's content
  // color on every variant. Skipped for reduced motion (the press
  // morph and hover tints still give feedback) and for disabled
  // buttons.
  #ripple(container, x, y) {
    if (this.hasAttribute("disabled")) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const rect = container.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const size = Math.max(rect.width, rect.height) * 2.2;
    const el = document.createElement("ripple");
    el.style.width = el.style.height = `${size}px`;
    el.style.left = `${x - rect.left}px`;
    el.style.top = `${y - rect.top}px`;
    container.appendChild(el);
    const anim = el.animate(
      [
        { transform: "translate(-50%, -50%) scale(0.15)", opacity: 0.12 },
        { transform: "translate(-50%, -50%) scale(1)", opacity: 0 },
      ],
      { duration: 450, easing: "cubic-bezier(0.2, 0, 0, 1)" }
    );
    anim.onfinish = () => el.remove();
    setTimeout(() => el.remove(), 600);
  }

  #rippleFromCenter(container) {
    const r = container.getBoundingClientRect();
    this.#ripple(container, r.left + r.width / 2, r.top + r.height / 2);
  }

  // -- leaf button ------------------------------------------------------------

  #initButton() {
    if (!this.hasAttribute("tabindex")) {
      this.setAttribute(
        "tabindex",
        this.hasAttribute("disabled") ? "-1" : "0"
      );
    }
    if (!this.hasAttribute("role")) this.setAttribute("role", "button");
    if (this.hasAttribute("disabled")) {
      this.setAttribute("aria-disabled", "true");
    }

    if (this.hasAttribute("toggle")) {
      if (!this.hasAttribute("selected") && !this.hasAttribute("unselected")) {
        this.setAttribute("unselected", "");
      }
      this.setAttribute(
        "aria-pressed",
        String(this.hasAttribute("selected"))
      );
    }

    if (this.hasAttribute("href")) {
      this.addEventListener("click", () => {
        if (this.hasAttribute("disabled")) return;
        window.location = this.getAttribute("href");
      });
    }

    const container = this.querySelector(":scope > container");
    if (container) {
      this.addEventListener("pointerdown", (e) => {
        this.#ripple(container, e.clientX, e.clientY);
      });
    }

    this.addEventListener("keydown", (e) => {
      if (this.hasAttribute("disabled")) return;
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        if (!e.repeat && container) this.#rippleFromCenter(container);
        this.click();
      }
    });

    this.addEventListener("click", (e) => {
      if (this.hasAttribute("disabled")) return;
      const detail = { value: this.value, button: this, event: e };
      // A standalone toggle flips itself; inside a group the group decides.
      if (this.hasAttribute("toggle") && !this.#inGroup()) {
        const on = !this.hasAttribute("selected");
        this.#setSelected(on);
        detail.selected = on;
      }
      this.#emit(detail);
    });
  }

  // -- split ------------------------------------------------------------------
  // Host is a decorator: it styles/joins its two nmui-button children and
  // turns the last one (the menu arrow) into an [open] toggle on the host.

  #initSplit() {
    const kids = [...this.children].filter((el) => el.tagName === "NMUI-BUTTON");
    this.#propagate(kids);
    const menuBtn = kids[kids.length - 1];
    if (!menuBtn) return;
    menuBtn.setAttribute("aria-haspopup", "true");
    menuBtn.setAttribute("aria-expanded", "false");

    this.addEventListener("change", (e) => {
      if (e.target !== menuBtn) return;
      e.stopPropagation();
      const open = !this.hasAttribute("open");
      this.toggleAttribute("open", open);
      menuBtn.setAttribute("aria-expanded", String(open));
      this.#emit({
        value: menuBtn.getAttribute("value"),
        button: menuBtn,
        open,
        event: e.detail?.event,
      });
    });
  }

  // -- fab menu -----------------------------------------------------------------
  // The FAB is the trigger; nmui-button children move into a <menu> that
  // opens above it. Picking an action closes the menu.

  #initFabMenu() {
    const actions = [...this.children].filter(
      (el) => el.tagName === "NMUI-BUTTON" || el.tagName === "BUTTON"
    );
    const menu = document.createElement("menu");
    actions.forEach((a) => menu.appendChild(a));
    this.appendChild(menu);
    this.#wrapContent();
    // While open, the trigger shows the close glyph; remember the
    // authored icon so closing can restore it.
    this.#fabIcon = this.querySelector(":scope > container > icon");
    this.#fabIconText = this.#fabIcon?.textContent ?? "";

    if (!this.hasAttribute("tabindex")) {
      this.setAttribute(
        "tabindex",
        this.hasAttribute("disabled") ? "-1" : "0"
      );
    }
    if (!this.hasAttribute("role")) this.setAttribute("role", "button");
    this.setAttribute("aria-haspopup", "true");
    this.setAttribute("aria-expanded", "false");

    const fabContainer = this.querySelector(":scope > container");
    if (fabContainer) {
      this.addEventListener("pointerdown", (e) => {
        this.#ripple(fabContainer, e.clientX, e.clientY);
      });
    }

    this.addEventListener("click", (e) => {
      if (this.hasAttribute("disabled")) return;
      const t = e.target instanceof Element ? e.target : null;
      if (t?.closest("menu")) return this.close();
      if (t === this || t?.closest("container")) this.toggle();
    });

    this.addEventListener("keydown", (e) => {
      if (e.key === "Escape") return this.close();
      if (e.target === this && (e.key === "Enter" || e.key === " ")) {
        e.preventDefault();
        if (this.hasAttribute("disabled")) return;
        if (!e.repeat && fabContainer) this.#rippleFromCenter(fabContainer);
        this.toggle();
      }
    });
  }

  #onOutside = (e) => {
    if (!this.contains(e.target)) this.close();
  };

  #setOpen(on) {
    if (this.hasAttribute("open") === on) return;
    this.toggleAttribute("open", on);
    this.setAttribute("aria-expanded", String(on));
    if (this.#fabIcon && this.#fabIconText.trim() !== "") {
      this.#fabIcon.textContent = on ? "close" : this.#fabIconText;
    }
    if (on) document.addEventListener("pointerdown", this.#onOutside);
    else document.removeEventListener("pointerdown", this.#onOutside);
    this.#emit({ value: this.value, button: this, open: on });
  }

  open() {
    this.#setOpen(true);
  }

  close() {
    this.#setOpen(false);
  }

  toggle() {
    this.#setOpen(!this.hasAttribute("open"));
  }

  // -- group ------------------------------------------------------------------
  // The host is a controller: it selects its direct nmui-button children,
  // which announce themselves with "change". [multiple] toggles children
  // independently instead of single-selecting.

  #initGroup() {
    const kids = () =>
      [...this.children].filter((el) => el.tagName === "NMUI-BUTTON");

    this.#propagate(kids());

    const select = (picked) => {
      kids().forEach((k) => {
        k.removeAttribute("selected");
        k.setAttribute("unselected", "");
      });
      if (picked) {
        picked.removeAttribute("unselected");
        picked.setAttribute("selected", "");
      }
    };

    kids().forEach((k) => {
      if (!k.hasAttribute("selected")) k.setAttribute("unselected", "");
    });

    const multiple = this.hasAttribute("multiple");

    const onPick = (picked, originalEvent) => {
      if (!picked || picked === this) return;
      if (picked.hasAttribute("disabled") || picked.disabled) return;
      if (multiple) {
        const on = !picked.hasAttribute("selected");
        picked.toggleAttribute("selected", on);
        picked.toggleAttribute("unselected", !on);
        if (picked.tagName === "NMUI-BUTTON" && picked.hasAttribute("toggle")) {
          picked.setAttribute("aria-pressed", String(on));
        }
        this.#emit({ value: picked.getAttribute("value"), button: picked, selected: on, event: originalEvent });
        return;
      }
      select(picked);
      this.#emit({ value: picked.getAttribute("value"), button: picked, event: originalEvent });
    };

    // Children announce via "change"; swallow it here and re-emit with
    // the group as the source.
    this.addEventListener("change", (e) => {
      if (e.target === this) return;
      e.stopPropagation();
      const picked = e.detail?.button;
      if (picked && picked.parentElement === this) onPick(picked, e);
    });
  }
}

if (!customElements.get("nmui-button")) {
  customElements.define("nmui-button", NMUIButton);
}

export { NMUIButton };
