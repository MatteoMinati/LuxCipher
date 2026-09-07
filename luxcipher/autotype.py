"""Global hotkey and keystroke injection for auto-type on Windows.

Auto-type is the feature that turns a vault from something you consult into
something you use: press a hotkey on a login form and the credentials are typed
for you, with no clipboard involved.

It is also the only feature that sends secrets into a window this application
does not own, so the matching rules in `match_credential` are deliberately
conservative. They are pure functions, separated from the Win32 layer, because
they are the part worth testing exhaustively.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import threading
from typing import Any, Callable, Iterable, Sequence


# Win32 constants
WM_HOTKEY = 0x0312
WM_QUIT = 0x0012
MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
MOD_NOREPEAT = 0x4000

INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

VK_TAB = 0x09
VK_RETURN = 0x0D

# Ctrl+Alt+L, chosen to avoid the common editor and browser bindings.
DEFAULT_HOTKEY_MODIFIERS = MOD_CONTROL | MOD_ALT | MOD_NOREPEAT
DEFAULT_HOTKEY_VK = ord("L")
DEFAULT_HOTKEY_LABEL = "Ctrl+Alt+L"

# A service name shorter than this matches too much to be trusted against an
# arbitrary window title.
MIN_MATCHABLE_SERVICE_LENGTH = 3


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wt.LONG),
        ("dy", wt.LONG),
        ("mouseData", wt.DWORD),
        ("dwFlags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", wt.WPARAM),
    ]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wt.WORD),
        ("wScan", wt.WORD),
        ("dwFlags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", wt.WPARAM),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wt.DWORD), ("wParamL", wt.WORD), ("wParamH", wt.WORD)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT), ("hi", _HARDWAREINPUT)]


class _INPUT(ctypes.Structure):
    # The union must be declared in full: SendInput validates cbSize against the
    # real INPUT layout, whose size is driven by the largest member.
    _anonymous_ = ("u",)
    _fields_ = [("type", wt.DWORD), ("u", _INPUTUNION)]


def _user32() -> Any:
    return ctypes.windll.user32


# --- matching -------------------------------------------------------------


def normalize_window_title(title: str | None) -> str:
    return (title or "").strip().lower()


def match_credential(
    window_title: str | None,
    accounts: Iterable[Sequence[Any]],
) -> Sequence[Any] | None:
    """Pick the credential whose service best matches a window title.

    `accounts` are rows shaped like AccountStore returns them:
    (id, service, username, password, created_at, updated_at).

    The rules, and why each one exists:

    - The service name must appear in the window title. Titles are what a
      browser or application shows, so "GitHub" matches "Sign in to GitHub -
      Chrome".
    - Service names shorter than three characters never match. A two-letter
      service would fire on almost any title.
    - When several services match, the longest one wins, because it is the more
      specific: "GitHub Enterprise" beats "GitHub".
    - When several credentials tie, the most recently updated wins. That is a
      guess, but a safe one: they are all for the same service, so the worst
      case is a failed login rather than a password typed somewhere it does not
      belong.
    - No match returns None, and the caller must type nothing. Typing a guess
      into an unknown window is how a password manager leaks a password.
    """
    title = normalize_window_title(window_title)
    if not title:
        return None

    best: Sequence[Any] | None = None
    best_key: tuple[int, str] | None = None

    for row in accounts:
        service = str(row[1] or "").strip().lower()
        if len(service) < MIN_MATCHABLE_SERVICE_LENGTH or service not in title:
            continue

        updated_at = str(row[5]) if len(row) > 5 and row[5] else ""
        key = (len(service), updated_at)
        if best_key is None or key > best_key:
            best, best_key = row, key

    return best


# --- keystroke injection --------------------------------------------------


def _key_event(vk: int, scan: int, flags: int) -> _INPUT:
    event = _INPUT()
    event.type = INPUT_KEYBOARD
    event.ki = _KEYBDINPUT(wVk=vk, wScan=scan, dwFlags=flags, time=0, dwExtraInfo=0)
    return event


def _send(events: list[_INPUT]) -> bool:
    if not events:
        return True

    array = (_INPUT * len(events))(*events)
    user32 = _user32()
    user32.SendInput.argtypes = [wt.UINT, ctypes.POINTER(_INPUT), ctypes.c_int]
    user32.SendInput.restype = wt.UINT
    sent = user32.SendInput(len(events), array, ctypes.sizeof(_INPUT))
    return sent == len(events)


def type_text(text: str) -> bool:
    """Type text as Unicode, so the layout of the target keyboard is irrelevant."""
    # Encoding to UTF-16 means characters outside the BMP arrive as the
    # surrogate pairs Windows expects, rather than being dropped.
    encoded = text.encode("utf-16-le", errors="ignore")

    events: list[_INPUT] = []
    for index in range(0, len(encoded) - 1, 2):
        code = encoded[index] | (encoded[index + 1] << 8)
        events.append(_key_event(0, code, KEYEVENTF_UNICODE))
        events.append(_key_event(0, code, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP))
    return _send(events)


def press_key(vk: int) -> bool:
    return _send([_key_event(vk, 0, 0), _key_event(vk, 0, KEYEVENTF_KEYUP)])


def foreground_window() -> tuple[int, str]:
    """Return the handle and title of the window currently receiving input."""
    try:
        user32 = _user32()
        user32.GetForegroundWindow.restype = wt.HWND
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return 0, ""

        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return int(hwnd), ""

        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buffer, length + 1)
        return int(hwnd), buffer.value
    except Exception:
        return 0, ""


def type_credential(username: str, password: str, expected_hwnd: int) -> bool:
    """Type username, Tab, password, Enter into the foreground window.

    `expected_hwnd` is re-checked immediately before typing. Between the hotkey
    firing and this call the user may have switched windows, and the whole point
    of the check is that the password must never land somewhere else.
    """
    hwnd, _ = foreground_window()
    if not hwnd or hwnd != expected_hwnd:
        return False

    if username:
        if not type_text(username):
            return False
        if not press_key(VK_TAB):
            return False

    if not type_text(password):
        return False

    return press_key(VK_RETURN)


# --- global hotkey --------------------------------------------------------


class HotkeyListener:
    """Registers a system-wide hotkey and calls back when it is pressed.

    RegisterHotKey delivers WM_HOTKEY to the queue of the thread that registered
    it, so registration and the message loop have to live on the same thread.
    That is why this owns a thread rather than borrowing one.
    """

    def __init__(
        self,
        callback: Callable[[], None],
        modifiers: int = DEFAULT_HOTKEY_MODIFIERS,
        virtual_key: int = DEFAULT_HOTKEY_VK,
        hotkey_id: int = 1,
    ) -> None:
        self._callback = callback
        self._modifiers = modifiers
        self._virtual_key = virtual_key
        self._hotkey_id = hotkey_id
        self._thread: threading.Thread | None = None
        self._thread_id: int | None = None
        self._registered = threading.Event()
        self._ok = False

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and self._ok)

    def start(self, timeout: float = 2.0) -> bool:
        """Start listening. Returns False when the hotkey is already taken."""
        if self.is_running:
            return True

        self._registered.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="LuxCipherHotkey"
        )
        self._thread.start()
        self._registered.wait(timeout)
        return self._ok

    def stop(self) -> None:
        if self._thread_id:
            try:
                user32 = _user32()
                user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
            except Exception:
                pass
        self._ok = False

    def _run(self) -> None:
        user32 = _user32()
        try:
            kernel32 = ctypes.windll.kernel32
            self._thread_id = int(kernel32.GetCurrentThreadId())

            self._ok = bool(
                user32.RegisterHotKey(None, self._hotkey_id, self._modifiers, self._virtual_key)
            )
        except Exception:
            self._ok = False
        finally:
            self._registered.set()

        if not self._ok:
            return

        try:
            message = wt.MSG()
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                if message.message == WM_HOTKEY and message.wParam == self._hotkey_id:
                    try:
                        self._callback()
                    except Exception:
                        # A failing callback must not kill the listener.
                        pass
        except Exception:
            pass
        finally:
            try:
                user32.UnregisterHotKey(None, self._hotkey_id)
            except Exception:
                pass
            self._ok = False
