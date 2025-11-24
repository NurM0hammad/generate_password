
import argparse
import string
import secrets
import sys

# Try optional clipboard support
try:
    import pyperclip
    _HAS_PYPERCLIP = True
except Exception:
    _HAS_PYPERCLIP = False

# Try optional GUI support (Tkinter is in stdlib)
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    _HAS_TK = True
except Exception:
    _HAS_TK = False

# Ambiguous characters often excluded from passwords
AMBIGUOUS = set("Il1O0`'\".,;:")  # add/remove as you prefer

def build_charset(use_lower, use_upper, use_digits, use_symbols, exclude_ambiguous):
    parts = []
    if use_lower:
        parts.append(string.ascii_lowercase)
    if use_upper:
        parts.append(string.ascii_uppercase)
    if use_digits:
        parts.append(string.digits)
    if use_symbols:
        # common symbols set; you can expand or shrink this
        parts.append("!@#$%^&*()-_=+[]{}<>?/")
    if not parts:
        raise ValueError("At least one character type must be selected.")
    if exclude_ambiguous:
        parts = [''.join(ch for ch in s if ch not in AMBIGUOUS) for s in parts]
    # Filter out any empty parts (could happen if excluding ambiguous removed all chars)
    parts = [p for p in parts if p]
    if not parts:
        raise ValueError("Character sets became empty after excluding ambiguous characters.")
    return parts

def generate_password(length, use_lower=True, use_upper=True, use_digits=True, use_symbols=True, exclude_ambiguous=False):
    """
    Generate a secure password:
    - length: desired length (int)
    - boolean flags to include each character type
    - exclude_ambiguous: if True, ambiguous characters removed
    Ensures at least one char from each selected category if length allows.
    """
    if length <= 0:
        raise ValueError("Length must be a positive integer.")

    parts = build_charset(use_lower, use_upper, use_digits, use_symbols, exclude_ambiguous)
    # flatten all chars to a single pool
    pool = ''.join(parts)

    if length < len(parts):
        # Not enough length to guarantee at least one char from each selected type.
        # We'll still produce a secure password but can't guarantee category coverage.
        # Use secrets.choice to fill.
        return ''.join(secrets.choice(pool) for _ in range(length))

    # Guarantee at least one from each selected part
    password_chars = [secrets.choice(part) for part in parts]

    # Fill the rest
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(pool) for _ in range(remaining)]

    # Shuffle securely
    # simple Fisher-Yates using secrets.randbelow
    for i in range(len(password_chars)-1, 0, -1):
        j = secrets.randbelow(i+1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return ''.join(password_chars)

def cli_main():
    parser = argparse.ArgumentParser(description="Secure Password Generator (CLI & GUI)")
    parser.add_argument("--length", "-l", type=int, default=16, help="Password length (default: 16)")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous characters like 'I', 'l', '1', 'O', '0'")
    parser.add_argument("--count", "-c", type=int, default=1, help="How many passwords to generate (default: 1)")
    parser.add_argument("--gui", action="store_true", help="Launch Tkinter GUI (if available)")
    parser.add_argument("--copy", action="store_true", help="Copy the last generated password to clipboard (requires pyperclip)")
    args = parser.parse_args()

    if args.gui:
        if not _HAS_TK:
            print("Tkinter is not available in your environment. Install tkinter or run without --gui.", file=sys.stderr)
            sys.exit(1)
        launch_gui()  # will not return until GUI closed
        return

    use_lower = not args.no_lower
    use_upper = not args.no_upper
    use_digits = not args.no_digits
    use_symbols = not args.no_symbols

    try:
        results = []
        for _ in range(max(1, args.count)):
            pwd = generate_password(
                args.length,
                use_lower=use_lower,
                use_upper=use_upper,
                use_digits=use_digits,
                use_symbols=use_symbols,
                exclude_ambiguous=args.exclude_ambiguous
            )
            results.append(pwd)
            print(pwd)
        if args.copy:
            if _HAS_PYPERCLIP:
                pyperclip.copy(results[-1])
                print("\nLast password copied to clipboard.")
            else:
                print("\npyperclip not installed — cannot copy to clipboard. Install with: pip install pyperclip")
    except ValueError as e:
        print("Error:", e, file=sys.stderr)
        sys.exit(2)

# ---------- Minimal Tkinter GUI ----------
def launch_gui():
    if not _HAS_TK:
        raise RuntimeError("Tkinter is not available.")

    root = tk.Tk()
    root.title("Password Generator")
    root.geometry("480x360")
    root.resizable(False, False)

    frm = ttk.Frame(root, padding=12)
    frm.pack(expand=True, fill="both")

    # Controls
    length_var = tk.IntVar(value=16)
    lower_var = tk.BooleanVar(value=True)
    upper_var = tk.BooleanVar(value=True)
    digits_var = tk.BooleanVar(value=True)
    symbols_var = tk.BooleanVar(value=True)
    ambiguous_var = tk.BooleanVar(value=False)

    ttk.Label(frm, text="Length:").grid(column=0, row=0, sticky="w")
    length_spin = ttk.Spinbox(frm, from_=4, to=128, textvariable=length_var, width=6)
    length_spin.grid(column=1, row=0, sticky="w")

    ttk.Checkbutton(frm, text="Lowercase", variable=lower_var).grid(column=0, row=1, sticky="w")
    ttk.Checkbutton(frm, text="Uppercase", variable=upper_var).grid(column=1, row=1, sticky="w")
    ttk.Checkbutton(frm, text="Digits", variable=digits_var).grid(column=0, row=2, sticky="w")
    ttk.Checkbutton(frm, text="Symbols", variable=symbols_var).grid(column=1, row=2, sticky="w")
    ttk.Checkbutton(frm, text="Exclude ambiguous (I, l, 1, O, 0)", variable=ambiguous_var).grid(column=0, row=3, columnspan=2, sticky="w")

    result_var = tk.StringVar(value="")
    result_entry = ttk.Entry(frm, textvariable=result_var, font=("Consolas", 12), width=40)
    result_entry.grid(column=0, row=5, columnspan=2, pady=(12,6))

    def do_generate():
        try:
            pwd = generate_password(
                length_var.get(),
                use_lower=lower_var.get(),
                use_upper=upper_var.get(),
                use_digits=digits_var.get(),
                use_symbols=symbols_var.get(),
                exclude_ambiguous=ambiguous_var.get()
            )
            result_var.set(pwd)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_clipboard():
        val = result_var.get()
        if not val:
            messagebox.showinfo("Info", "No password to copy.")
            return
        if _HAS_PYPERCLIP:
            pyperclip.copy(val)
            messagebox.showinfo("Copied", "Password copied to clipboard.")
        else:
            # Try Tk clipboard as fallback
            try:
                root.clipboard_clear()
                root.clipboard_append(val)
                messagebox.showinfo("Copied", "Password copied to clipboard via Tk clipboard.")
            except Exception:
                messagebox.showwarning("Clipboard", "Clipboard not available. Install pyperclip to enable copying.")

    gen_btn = ttk.Button(frm, text="Generate", command=do_generate)
    gen_btn.grid(column=0, row=4, pady=(8,0), sticky="w")
    copy_btn = ttk.Button(frm, text="Copy", command=copy_clipboard)
    copy_btn.grid(column=1, row=4, pady=(8,0), sticky="e")

    # Quick generate on startup
    do_generate()

    root.mainloop()

if __name__ == "__main__":
    cli_main()
