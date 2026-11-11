/* GENERATED for Deadband from nmui — do not hand-edit.
   The CSS-module import header of the original is removed:
   WebKit (Tauri's macOS/Linux webview) cannot parse it.
   This component's CSS is loaded by ui/index.html instead.
   Regenerate with tools/vendor_nmui.py. */

/**
 * <nmui-text-field> — M3 text field. Decorates a native
 * input or textarea plus its label, so forms, validation,
 * and keyboard behavior come free.
 *
 *   <nmui-text-field>
 *     <label>Email</label>
 *     <input type="email">
 *     <small>We never share it</small>
 *   </nmui-text-field>
 *
 * Bare = filled; [outlined] for the outlined variant. The
 * label floats when the field is focused or populated.
 * <small> is supporting text; <small error> is error text
 * — it REPLACES the supporting text while the host carries
 * [error] (set it from your validation), and an error icon
 * is added automatically unless you author a trailing
 * element of your own.
 *
 * Adornments, all optional:
 *   <icon leading> / <icon trailing>     24dp icons
 *   <button trailing> / <nmui-button trailing>  interactive
 *   <span prefix>$</span>                prefix text
 *   <span suffix>@gmail.com</span>       suffix text
 * A character counter appears automatically when the input
 * has a maxlength. Supporting/error text, prefix, suffix,
 * and the counter are wired into the input's
 * aria-describedby; [error] also sets aria-invalid.
 *
 * Programmatic sets (input.value = "x") fire no events, so
 * the input's own setters are reflected to the host, like
 * the other form controls; form resets re-sync too. The
 * host's .value delegates to the input. A <textarea> makes
 * a text area (fixed height from its rows).
 */
let uid = 0;

class NMUITextField extends HTMLElement {
  #ready = false;
  #input = null;
  #label = null;
  #field = null;
  #counter = null;
  #authoredDescribedby = "";

  static observedAttributes = ["error"];

  connectedCallback() {
    if (this.#ready) return;
    this.#ready = true;

    this.#input = this.querySelector(":scope > input, :scope > textarea");
    if (!this.#input) return;
    const input = this.#input;
    if (input.tagName === "TEXTAREA") this.setAttribute("multiline", "");

    this.#label = this.querySelector(":scope > label");
    if (this.#label) {
      if (!input.id) input.id = `nmui-tf-${++uid}`;
      if (!this.#label.htmlFor) this.#label.htmlFor = input.id;
    } else {
      this.setAttribute("nolabel", "");
    }

    const leading = [...this.querySelectorAll(":scope > [leading]")];
    const trailing = [...this.querySelectorAll(":scope > [trailing]")];
    const prefix = this.querySelector(":scope > [prefix]");
    const suffix = this.querySelector(":scope > [suffix]");
    const supporting = this.querySelector(":scope > small:not([error])");
    const errorText = this.querySelector(":scope > small[error]");
    if (leading.length) this.setAttribute("has-leading", "");
    if (trailing.length) this.setAttribute("has-trailing", "");
    for (const el of [prefix, suffix]) {
      if (el && !el.id) el.id = `nmui-tf-${++uid}`;
    }
    if (supporting && !supporting.id) supporting.id = `nmui-tf-${++uid}`;
    if (errorText && !errorText.id) errorText.id = `nmui-tf-${++uid}`;

    // Field wrapper: [frame pieces (outlined)] leading,
    // input wrap (prefix, input, suffix), trailing.
    const field = document.createElement("field");
    this.#field = field;
    if (this.hasAttribute("outlined")) {
      for (const part of ["start", "notch", "end"]) {
        const piece = document.createElement(`frame-${part}`);
        field.appendChild(piece);
      }
    }
    const wrap = document.createElement("inputwrap");
    for (const el of leading) field.appendChild(el);
    if (prefix) wrap.appendChild(prefix);
    wrap.appendChild(input);
    if (suffix) wrap.appendChild(suffix);
    field.appendChild(wrap);
    for (const el of trailing) field.appendChild(el);
    if (!trailing.length) {
      const errIcon = document.createElement("icon");
      errIcon.textContent = "error";
      errIcon.setAttribute("error-icon", "");
      errIcon.setAttribute("aria-label", "Error");
      field.appendChild(errIcon);
    }
    this.prepend(field);
    // The label overlays the field; move it after so it
    // paints above the frame pieces.
    if (this.#label) this.appendChild(this.#label);

    // Supporting row: supporting/error text + counter.
    if (input.maxLength > 0) {
      this.#counter = document.createElement("counter");
      this.#counter.id = `nmui-tf-${++uid}`;
    }
    if (supporting || errorText || this.#counter) {
      const row = document.createElement("supporting");
      if (supporting) row.appendChild(supporting);
      if (errorText) row.appendChild(errorText);
      if (this.#counter) row.appendChild(this.#counter);
      this.appendChild(row);
    }

    this.#authoredDescribedby = input.getAttribute("aria-describedby") || "";

    input.addEventListener("input", () => this.#sync());
    input.addEventListener("focus", () => {
      this.setAttribute("focused", "");
      this.#sync();
    });
    input.addEventListener("blur", () => {
      this.removeAttribute("focused");
      this.#sync();
    });
    if (input.form) {
      input.form.addEventListener("reset", () => setTimeout(() => this.#sync(), 0));
    }

    // Reflect programmatic property sets (see JSDoc). The
    // setter's receiver is the input, so sync is captured
    // as a closure over the host, not called as a method.
    const sync = () => this.#sync();
    const proto = Object.getPrototypeOf(input);
    for (const prop of ["value", "disabled"]) {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || typeof desc.set !== "function") continue;
      Object.defineProperty(input, prop, {
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

    // Clicks on the container focus the input (label clicks
    // land natively); interactive trailing elements keep
    // their own clicks.
    field.addEventListener("pointerdown", (e) => {
      if (input.disabled) return;
      if (e.target.closest("button, nmui-button, a")) return;
      if (e.target !== input) {
        e.preventDefault();
        input.focus();
      }
    });

    if (typeof ResizeObserver !== "undefined") {
      new ResizeObserver(() => this.#measureNotch()).observe(this);
    }
    this.#sync();
  }

  attributeChangedCallback(name) {
    if (name === "error" && this.#ready) this.#sync();
  }

  get value() {
    return this.#input ? this.#input.value : "";
  }

  set value(v) {
    if (this.#input) this.#input.value = v;
  }

  #sync() {
    const input = this.#input;
    if (!input) return;
    const populated = input.value.length > 0;
    this.toggleAttribute("populated", populated);
    this.toggleAttribute("disabled", input.disabled);
    this.toggleAttribute("readonly", input.readOnly);
    const floated = populated || this.hasAttribute("focused");
    this.toggleAttribute("floated", floated);

    const error = this.hasAttribute("error");
    if (error) input.setAttribute("aria-invalid", "true");
    else input.removeAttribute("aria-invalid");

    // aria-describedby: the visible supporting text (error
    // text replaces supporting text in error), then prefix,
    // suffix, counter — after any author-provided ids.
    const ids = [];
    if (this.#authoredDescribedby) ids.push(this.#authoredDescribedby);
    const visible = this.querySelector(
      error ? ":scope > supporting > small[error]" : ":scope > supporting > small:not([error])"
    );
    if (visible?.id) ids.push(visible.id);
    for (const part of ["prefix", "suffix"]) {
      const el = this.querySelector(`:scope > field > inputwrap > [${part}]`);
      if (el?.id) ids.push(el.id);
    }
    if (this.#counter) {
      const len = input.value.length;
      const max = input.maxLength;
      this.#counter.textContent = `${len} / ${max}`;
      this.#counter.setAttribute("aria-label", `Character count, ${len}/${max}`);
      this.#counter.toggleAttribute("over", len > max);
      ids.push(this.#counter.id);
    }
    if (ids.length) input.setAttribute("aria-describedby", ids.join(" "));
    else input.removeAttribute("aria-describedby");

    this.#measureNotch();
  }

  // The outlined notch: when the label floats it sits in a
  // gap in the top outline; --notch is that gap's width
  // (label + its 4dp side padding), measured in the label's
  // floated (body-small) size.
  #measureNotch() {
    if (!this.#field || !this.hasAttribute("outlined") || !this.#label) return;
    const notch = this.hasAttribute("floated")
      ? Math.ceil(this.#label.offsetWidth) + 8
      : 0;
    this.#field.style.setProperty("--notch", `${notch}px`);
  }
}

if (!customElements.get("nmui-text-field")) {
  customElements.define("nmui-text-field", NMUITextField);
}

export { NMUITextField };
