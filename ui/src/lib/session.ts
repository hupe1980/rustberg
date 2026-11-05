// The credential lives in this tab's session storage only: it survives a reload, is gone when the tab
// closes, and never travels in a URL or a cookie. It is cleared on sign-out and whenever the server
// rejects it.
const KEY = "rustberg.credential";

export function credential(): string | null {
  try {
    return sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function remember(value: string): void {
  sessionStorage.setItem(KEY, value.trim());
}

export function forget(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: nothing to forget */
  }
}
