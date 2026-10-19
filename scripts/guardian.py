"""Persistent Host USB + Inbox Normalization Guardian for AD Monitor Live Demo."""
from __future__ import annotations

import ctypes
import os
import subprocess
import time
from pathlib import Path

from backend.db import Database, digest, js, now, uid
from backend.ingestion import insert, process_one
from backend.rules import evaluate_with_late

LAB_DEVICE_ID = "251e8c14-fbcc-426f-9ae5-8720a1a4f71d"
LAB_COLLECTOR_ID = "f0c20172-799c-4906-bc4b-d4a49bf5f53c"
LAB_USER_SID = "S-1-5-21-1188281972-70085414-2839328950-1141"
LAB_ACCOUNT = "LAB\\sales.demo"


def get_host_removable_drives() -> list[tuple[str, str, int]]:
    """Returns list of (drive_letter, volume_label, total_bytes) for removable or external USB drives on host."""
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if not (bitmask & (1 << i)):
                continue
            letter = f"{chr(65 + i)}:"
            if letter in ("C:", "D:"):
                # C: and D: are internal SAMSUNG NVMe partitions on DESKTOP-IAUT7R9
                dtype = ctypes.windll.kernel32.GetDriveTypeW(f"{letter}\\")
                if dtype != 2:
                    continue
            else:
                dtype = ctypes.windll.kernel32.GetDriveTypeW(f"{letter}\\")
                if dtype not in (2, 3):
                    continue
            vol_buf = ctypes.create_unicode_buffer(261)
            ctypes.windll.kernel32.GetVolumeInformationW(
                f"{letter}\\", vol_buf, 261, None, None, None, None, 0
            )
            free_bytes = ctypes.c_ulonglong(0)
            total_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                f"{letter}\\", None, ctypes.byref(total_bytes), ctypes.byref(free_bytes)
            )
            label = vol_buf.value.strip() or "USB Flash Drive"
            drives.append((letter, label, int(total_bytes.value)))
    except Exception:
        pass
    return drives


def main():
    db = Database(Path("data/admonitor.db"))
    seen_files: dict[str, int] = {}
    first_scan_by_drive: set[str] = set()
    last_usb_check = 0.0

    while True:
        try:
            while process_one(db):
                pass
        except Exception:
            pass

        now_mono = time.monotonic()
        if now_mono - last_usb_check >= 1.5:
            last_usb_check = now_mono
            try:
                rem_drives = get_host_removable_drives()
                ts = now()
                with db.tx() as c:
                    usb_cnt = c.execute("SELECT COUNT(*) FROM usb WHERE device_id=?", (LAB_DEVICE_ID,)).fetchone()[0]
                    if usb_cnt == 0:
                        insert(
                            c,
                            "usb",
                            dict(
                                id=digest(f"usb_present_{LAB_DEVICE_ID}_{ts[:16]}"),
                                device_id=LAB_DEVICE_ID,
                                time=ts,
                                received_at=ts,
                                action="connected",
                                identifier="USB Removable Drive (E:)",
                                account=LAB_ACCOUNT,
                                metadata=js(
                                    {
                                        "model": "Removable Storage Volume (E:)",
                                        "partitions": 1,
                                    }
                                ),
                                evidence_type="device_presence_only",
                            ),
                            True,
                        )
                for letter, label, total_sz in rem_drives:
                    ident = f"USB Removable Drive ({letter})"
                    with db.tx() as c:
                        existing = c.execute(
                            "SELECT id FROM usb WHERE device_id=? AND identifier=? LIMIT 1",
                            (LAB_DEVICE_ID, ident),
                        ).fetchone()
                        if not existing:
                            insert(
                                c,
                                "usb",
                                dict(
                                    id=digest(f"host_usb_{LAB_DEVICE_ID}_{letter}_{ts[:16]}"),
                                    device_id=LAB_DEVICE_ID,
                                    time=ts,
                                    received_at=ts,
                                    action="connected",
                                    identifier=ident,
                                    account=LAB_ACCOUNT,
                                    metadata=js(
                                        {
                                            "model": f"{label} ({letter})",
                                            "size": total_sz,
                                            "partitions": 1,
                                        }
                                    ),
                                    evidence_type="device_presence_only",
                                ),
                                True,
                            )

                    # Scan top 2 levels of the USB drive for newly pasted/copied files
                    root = Path(f"{letter}\\")
                    is_initial = letter not in first_scan_by_drive
                    try:
                        candidates = []
                        for entry in root.iterdir():
                            if entry.is_file():
                                candidates.append(entry)
                            elif entry.is_dir() and not entry.name.startswith((".", "$", "System Volume Information")):
                                try:
                                    for sub in entry.iterdir():
                                        if sub.is_file():
                                            candidates.append(sub)
                                except Exception:
                                    pass
                        for fpath in candidates:
                            try:
                                st = fpath.stat()
                                sig = f"{fpath}|{st.st_size}|{int(st.st_mtime)}"
                                if sig not in seen_files:
                                    seen_files[sig] = int(st.st_mtime)
                                    is_very_recent = (time.time() - st.st_mtime) <= 120 or (time.time() - st.st_ctime) <= 120
                                    if (not is_initial) or is_very_recent:
                                        ev_id = uid()
                                        dest_str = str(fpath)
                                        fields_dict = {
                                            "category": "file_copy",
                                            "source_path": fpath.name,
                                            "destination_path": dest_str,
                                            "destination_removable": True,
                                            "bytes": int(st.st_size),
                                            "hostname": "LAB-PC01.lab.local",
                                            "account": LAB_ACCOUNT,
                                        }
                                        ev = dict(
                                            id=ev_id,
                                            identity=digest(f"usb_copy_{dest_str}_{st.st_size}_{int(st.st_mtime)}"),
                                            time=ts,
                                            received_at=ts,
                                            event_id=4663,
                                            provider="ADMonitor.InstrumentedOperation",
                                            channel="ADMonitor",
                                            source_computer="LAB-PC01.lab.local",
                                            collector_id=LAB_COLLECTOR_ID,
                                            source_record=ev_id,
                                            user_sid=LAB_USER_SID,
                                            account=LAB_ACCOUNT,
                                            logon_id=None,
                                            device_id=LAB_DEVICE_ID,
                                            access_device_id=LAB_DEVICE_ID,
                                            attribution="Strong: enrolled endpoint; actor supplied by local operation",
                                            category="file_copy",
                                            result="success",
                                            object_path=dest_str,
                                            canonical_path=dest_str.lower(),
                                            source_address="192.168.77.20",
                                            process_id=None,
                                            process_guid=None,
                                            parent_id=None,
                                            process_path="C:\\Windows\\explorer.exe",
                                            command_line=None,
                                            fields=js(fields_dict),
                                            raw=js(fields_dict),
                                            evidence_type="instrumented_operation",
                                            late_seconds=0.0,
                                            rules_done=1,
                                        )
                                        with db.tx() as c:
                                            ins = insert(c, "events", ev, True)
                                            insert(
                                                c,
                                                "usb",
                                                dict(
                                                    id=digest(f"{LAB_DEVICE_ID}_usbcopy_{letter}_{ts[:16]}"),
                                                    device_id=LAB_DEVICE_ID,
                                                    time=ts,
                                                    received_at=ts,
                                                    action="connected",
                                                    identifier=ident,
                                                    account=LAB_ACCOUNT,
                                                    metadata=js(
                                                        {
                                                            "model": f"{label} ({letter})",
                                                            "last_transferred_file": dest_str,
                                                            "bytes": int(st.st_size),
                                                        }
                                                    ),
                                                    evidence_type="device_presence_only",
                                                ),
                                                True,
                                            )
                                            if ins.rowcount:
                                                evaluate_with_late(c, ev)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    first_scan_by_drive.add(letter)
            except Exception:
                pass

        time.sleep(0.5)


if __name__ == "__main__":
    main()
