#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any, Dict, List, Optional, Tuple, cast

from flask import Flask, jsonify, request, send_from_directory, Response  # pyre-ignore
from werkzeug.utils import secure_filename  # pyre-ignore


APP_ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = APP_ROOT / "public"
DEFAULT_PORT = int(os.getenv("PORT", "3000"))
UPLOAD_DIR = Path("/tmp/dns_sinkhole_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso8601(value: str) -> Optional[datetime]:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def sse_message(event_name: str, payload: Dict[str, Any]) -> str:
    return f"event: {event_name}\ndata: {json.dumps(payload)}\n\n"


class CaptureManager:
    ACTIVE_STATES = {"starting", "running", "stopping"}

    def __init__(self, root: Path, max_events: int = 500, max_activity: int = 40) -> None:
        self.root = root
        self.monitor_script = root / "scripts" / "dns_monitor.py"
        self.lock = threading.RLock()
        self.events = deque(maxlen=max_events)
        self.activity = deque(maxlen=max_activity)
        self.subscribers: List[Queue] = []
        self.process: Optional[subprocess.Popen] = None
        self.worker: Optional[threading.Thread] = None
        self.stop_requested = False
        self.sequence = 0
        self.session = self._idle_session()

    def _default_config(self) -> Dict[str, Any]:
        return {
            "mode": "live",
            "preferredTool": "auto",
            "interface": "",
            "pcapPath": "",
            "mongoUri": "",
            "mongoDb": "dns_sinkhole",
            "mongoCollection": "dns_events",
            "limit": 0,
        }

    def _idle_session(self) -> Dict[str, Any]:
        return {
            "id": None,
            "status": "idle",
            "tool": None,
            "note": "Ready for a new capture session.",
            "startedAt": None,
            "endedAt": None,
            "lastEventAt": None,
            "eventsSeen": 0,
            "errors": [],
            "config": self._default_config(),
        }

    def _copy_session_locked(self) -> Dict[str, Any]:
        session = dict(self.session)
        session["config"] = dict(self.session.get("config", {}))
        session["errors"] = list(self.session.get("errors", []))
        return session

    def _add_activity_locked(self, message: str, level: str = "info") -> None:
        if not message:
            return

        entry = {"timestamp": utc_now(), "level": level, "message": message}
        latest = self.activity[0] if self.activity else None
        if latest and latest["message"] == message and latest["level"] == level:
            latest["timestamp"] = entry["timestamp"]
            return

        self.activity.appendleft(entry)

    def _push_error_locked(self, message: str) -> None:
        errors = cast(List[str], list(self.session.get("errors", [])))
        errors.append(message)
        self.session["errors"] = [e for i, e in enumerate(errors) if i >= len(errors) - 6]
        self._add_activity_locked(message, "error")

    def _search_match(self, event: Dict[str, Any], term: str) -> bool:
        haystack = " ".join(
            [
                event.get("domain", ""),
                event.get("recordType", ""),
                event.get("sourceIp", ""),
                event.get("destinationIp", ""),
                event.get("tool", ""),
                event.get("mode", ""),
                event.get("transport", ""),
            ]
        ).lower()
        return term in haystack

    def _build_summary_locked(self) -> Dict[str, Any]:
        events = list(self.events)
        domains = Counter(
            event["domain"]
            for event in events
            if event.get("domain") and event.get("domain") != "unknown"
        )
        source_ips = Counter(
            event["sourceIp"]
            for event in events
            if event.get("sourceIp") and event.get("sourceIp") != "unknown"
        )
        record_types = Counter(
            event["recordType"]
            for event in events
            if event.get("recordType") and event.get("recordType") != "UNKNOWN"
        )
        transports = Counter(event["transport"] for event in events if event.get("transport"))

        last_event_at = events[0]["timestamp"] if events else None
        events_per_minute = 0.0
        if len(events) >= 2:
            newest = parse_iso8601(events[0]["timestamp"])
            oldest = parse_iso8601(events[-1]["timestamp"])
            if newest and oldest:
                span_minutes = max((newest - oldest).total_seconds() / 60, 1 / 60)
                events_per_minute = float(f"{len(events) / span_minutes:.1f}")

        return {
            "totalEvents": len(events),
            "uniqueDomains": len(domains),
            "topDomain": domains.most_common(1)[0][0] if domains else None,
            "topSourceIp": source_ips.most_common(1)[0][0] if source_ips else None,
            "topRecordType": record_types.most_common(1)[0][0] if record_types else None,
            "lastEventAt": last_event_at,
            "eventsPerMinute": events_per_minute,
            "transportBreakdown": dict(transports),
            "recentActivity": list(self.activity),
        }

    def snapshot(self, search: str = "", limit: int = 0) -> Dict[str, Any]:
        with self.lock:
            events = cast(List[Dict[str, Any]], list(self.events))
            if search:
                term = search.strip().lower()
                events = [event for event in events if self._search_match(event, term)]
            if limit > 0:
                events = [e for i, e in enumerate(events) if i < limit]

            return {
                "data": events,
                "summary": self._build_summary_locked(),
                "captureSession": self._copy_session_locked(),
            }

    def _session_payload_locked(self) -> Dict[str, Any]:
        return {
            "captureSession": self._copy_session_locked(),
            "summary": self._build_summary_locked(),
        }

    def _broadcast(self, event_name: str, payload: Dict[str, Any]) -> None:
        stale: List[Queue] = []
        with self.lock:
            subscribers = list(self.subscribers)

        for subscriber in subscribers:
            try:
                subscriber.put_nowait((event_name, payload))
            except Full:
                stale.append(subscriber)

        if stale:
            with self.lock:
                for subscriber in stale:
                    if subscriber in self.subscribers:
                        self.subscribers.remove(subscriber)

    def subscribe(self) -> Queue:
        queue: Queue = Queue(maxsize=64)
        with self.lock:
            self.subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: Queue) -> None:
        with self.lock:
            if queue in self.subscribers:
                self.subscribers.remove(queue)

    def _normalize_event_locked(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.sequence += 1
        domain = str(payload.get("domain") or payload.get("queryName") or "unknown").strip() or "unknown"
        source_ip = str(payload.get("sourceIp") or "unknown").strip() or "unknown"
        destination_ip = str(payload.get("destinationIp") or payload.get("resolverIp") or "unknown").strip() or "unknown"
        record_type = str(payload.get("recordType") or payload.get("type") or "A").strip().upper() or "A"
        tool = str(payload.get("tool") or self.session.get("tool") or self.session["config"].get("preferredTool") or "auto")
        mode = str(payload.get("mode") or self.session["config"].get("mode") or "live")
        timestamp = str(payload.get("timestamp") or utc_now())

        return {
            "id": f"evt-{self.sequence}",
            "timestamp": timestamp,
            "domain": domain,
            "queryName": domain,
            "sourceIp": source_ip,
            "destinationIp": destination_ip,
            "resolverIp": destination_ip,
            "recordType": record_type,
            "type": record_type,
            "protocol": str(payload.get("protocol") or "DNS"),
            "transport": str(payload.get("transport") or "udp").lower(),
            "tool": tool,
            "mode": mode,
            "confidence": str(payload.get("confidence") or "observed"),
            "source": str(payload.get("source") or "python-monitor"),
        }

    def _handle_monitor_payload(self, payload: Dict[str, Any]) -> None:
        kind = payload.get("kind")
        if not kind:
            return

        if kind == "event":
            with self.lock:
                event = self._normalize_event_locked(payload)
                self.events.appendleft(event)
                self.session["eventsSeen"] = int(self.session.get("eventsSeen", 0)) + 1
                self.session["lastEventAt"] = event["timestamp"]
                if self.session.get("status") != "stopping":
                    self.session["status"] = "running"
                if payload.get("tool"):
                    self.session["tool"] = payload["tool"]
                self.session["note"] = f"Observed {event['recordType']} query for {event['domain']}"
                if self.session["eventsSeen"] in {1, 5} or self.session["eventsSeen"] % 25 == 0:
                    self._add_activity_locked(self.session["note"], "info")
                payload_data = {
                    "event": event,
                    "captureSession": self._copy_session_locked(),
                    "summary": self._build_summary_locked(),
                }
            self._broadcast("dns-event", payload_data)
            return

        if kind == "status":
            note = str(payload.get("note") or "").strip()
            status = str(payload.get("status") or "running").strip() or "running"
            with self.lock:
                self.session["status"] = status
                if payload.get("tool"):
                    self.session["tool"] = payload["tool"]
                if note:
                    self.session["note"] = note
                    self._add_activity_locked(note, "info")
                payload_data = self._session_payload_locked()
            self._broadcast("session", payload_data)
            return

        if kind == "error":
            message = str(payload.get("message") or "Unknown capture error").strip()
            with self.lock:
                self.session["status"] = "error"
                self.session["note"] = message
                self._push_error_locked(message)
                payload_data = self._session_payload_locked()
            self._broadcast("session", payload_data)

    def _build_command(self, config: Dict[str, Any]) -> List[str]:
        cmd = [
            sys.executable,
            str(self.monitor_script),
            "--mode",
            config["mode"],
            "--preferred-tool",
            config["preferredTool"],
            "--mongo-db",
            config["mongoDb"],
            "--mongo-collection",
            config["mongoCollection"],
        ]

        if config["interface"]:
            cmd.extend(["--interface", config["interface"]])
        if config["pcapPath"]:
            cmd.extend(["--pcap", config["pcapPath"]])
        if config["mongoUri"]:
            cmd.extend(["--mongo-uri", config["mongoUri"]])
        if config["limit"]:
            cmd.extend(["--limit", str(config["limit"])])

        return cmd

    def _consume_stderr(self, process: subprocess.Popen) -> None:
        stderr = process.stderr
        if not stderr:
            return

        for raw_line in stderr:
            line = raw_line.strip()
            if not line:
                continue
            with self.lock:
                self._push_error_locked(line)
                payload = self._session_payload_locked()
            self._broadcast("session", payload)

    def _run_capture(self, config: Dict[str, Any]) -> None:
        process: Optional[subprocess.Popen] = None
        stderr_thread: Optional[threading.Thread] = None
        return_code = 1

        try:
            process = subprocess.Popen(
                self._build_command(config),
                cwd=str(self.root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            with self.lock:
                self.process = process
                self.session["note"] = "DNS monitor subprocess started."
                payload = self._session_payload_locked()
            self._broadcast("session", payload)

            stderr_thread = threading.Thread(target=self._consume_stderr, args=(process,), daemon=True)
            stderr_thread.start()

            stdout = process.stdout
            if stdout:
                for raw_line in stdout:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        with self.lock:
                            self._push_error_locked(f"Unreadable monitor payload: {line}")
                            session_payload = self._session_payload_locked()
                        self._broadcast("session", session_payload)
                        continue

                    self._handle_monitor_payload(payload)

            return_code = process.wait()
        except FileNotFoundError:
            with self.lock:
                self.session["status"] = "error"
                self.session["note"] = "The DNS monitor script is missing."
                self._push_error_locked("Unable to locate scripts/dns_monitor.py")
                payload = self._session_payload_locked()
            self._broadcast("session", payload)
            return
        except Exception as exc:
            with self.lock:
                self.session["status"] = "error"
                self.session["note"] = f"Failed to start capture: {exc}"
                self._push_error_locked(str(exc))
                payload = self._session_payload_locked()
            self._broadcast("session", payload)
            return
        finally:
            if stderr_thread:
                stderr_thread.join(timeout=1.5)
            with self.lock:
                active_process = self.process
                if active_process is process:
                    self.process = None

                if self.stop_requested and self.session.get("status") != "error":
                    self.session["status"] = "stopped"
                    self.session["note"] = "Capture stopped by user."
                elif self.session.get("status") not in {"error", "stopped"}:
                    self.session["status"] = "completed" if return_code == 0 else "error"
                    self.session["note"] = (
                        "Capture finished successfully."
                        if return_code == 0
                        else f"Capture exited with status code {return_code}."
                    )

                self.session["endedAt"] = utc_now()
                self.stop_requested = False
                payload = self._session_payload_locked()
            self._broadcast("session", payload)

    def start(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        config = self._default_config()
        config["mode"] = str(payload.get("mode") or config["mode"]).strip().lower()
        config["preferredTool"] = str(payload.get("preferredTool") or config["preferredTool"]).strip().lower()
        config["interface"] = str(payload.get("interface") or "").strip()
        config["pcapPath"] = str(payload.get("pcapPath") or "").strip()
        config["mongoUri"] = str(payload.get("mongoUri") or "").strip()
        config["mongoDb"] = str(payload.get("mongoDb") or config["mongoDb"]).strip() or config["mongoDb"]
        config["mongoCollection"] = str(payload.get("mongoCollection") or config["mongoCollection"]).strip() or config["mongoCollection"]

        try:
            config["limit"] = max(int(payload.get("limit") or 0), 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("Event limit must be a non-negative integer.") from exc

        if config["mode"] not in {"live", "manual"}:
            raise ValueError("Mode must be live or manual.")
        if config["preferredTool"] not in {"auto", "scapy", "tshark"}:
            raise ValueError("Preferred tool must be auto, scapy, or tshark.")
        if config["mode"] == "manual" and not config["pcapPath"]:
            raise ValueError("Manual mode requires a PCAP path.")
        if config["mode"] == "manual":
            expanded_pcap = Path(config["pcapPath"]).expanduser()
            if not expanded_pcap.exists():
                raise ValueError("The selected PCAP file does not exist.")
            config["pcapPath"] = str(expanded_pcap)
        if not self.monitor_script.exists():
            raise ValueError("Monitor script is missing from scripts/dns_monitor.py.")

        with self.lock:
            proc = self.process
            if proc is not None and proc.poll() is None:
                raise RuntimeError("A capture session is already running.")

            session_id = f"session-{int(time.time() * 1000)}"
            self.stop_requested = False
            self.session = {
                "id": session_id,
                "status": "starting",
                "tool": config["preferredTool"],
                "note": "Preparing DNS capture.",
                "startedAt": utc_now(),
                "endedAt": None,
                "lastEventAt": None,
                "eventsSeen": 0,
                "errors": [],
                "config": config,
            }
            self.activity.clear()
            self._add_activity_locked("Preparing DNS capture.", "info")
            self.worker = threading.Thread(target=self._run_capture, args=(config,), daemon=True)
            worker = self.worker
            if worker is not None:
                worker.start()
            payload_data = self._session_payload_locked()

        self._broadcast("session", payload_data)
        return payload_data

    def stop(self) -> Tuple[Dict[str, Any], bool]:
        process: Optional[subprocess.Popen] = None
        with self.lock:
            proc_obj = self.process
            if proc_obj is not None and proc_obj.poll() is None:
                self.stop_requested = True
                self.session["status"] = "stopping"
                self.session["note"] = "Stop requested. Waiting for the monitor to shut down."
                self._add_activity_locked(self.session["note"], "warning")
                process = self.process
            else:
                if self.session.get("status") in self.ACTIVE_STATES:
                    self.session["status"] = "completed"
                self.session["note"] = "No active capture session was running."
                self._add_activity_locked(self.session["note"], "info")

            payload = self._session_payload_locked()

        if process:
            try:
                process.terminate()
            except Exception as exc:
                with self.lock:
                    self.session["status"] = "error"
                    self.session["note"] = f"Unable to stop capture cleanly: {exc}"
                    self._push_error_locked(self.session["note"])
                    payload = self._session_payload_locked()

        self._broadcast("session", payload)
        return payload, process is not None


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(PUBLIC_DIR), static_url_path="")
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB limit
    manager = CaptureManager(APP_ROOT)
    app.config["capture_manager"] = manager

    @app.route("/")
    def index() -> Any:
        return app.send_static_file("index.html")

    @app.route("/health")
    def health() -> Any:
        return jsonify({"status": "ok", "timestamp": utc_now()})

    @app.route("/api/dns-data")
    def dns_data() -> Any:
        search = request.args.get("search", "", type=str)
        limit = request.args.get("limit", 0, type=int)
        return jsonify(manager.snapshot(search=search, limit=limit))

    @app.route("/api/capture-status")
    def capture_status() -> Any:
        snapshot = manager.snapshot(limit=0)
        return jsonify(
            {
                "captureSession": snapshot["captureSession"],
                "summary": snapshot["summary"],
            }
        )

    @app.route("/api/capture/start", methods=["POST"])
    def capture_start() -> Any:
        payload = request.get_json(silent=True) or {}
        try:
            session_payload = manager.start(payload)
            return jsonify(session_payload), 202
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 409

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({"error": "File is too large. Maximum size is 50MB."}), 413

    @app.route("/api/upload-pcap", methods=["POST"])
    def upload_pcap() -> Any:
        try:
            if "pcap" not in request.files:
                return jsonify({"error": "No file part named 'pcap' found in the request."}), 400
            
            file = request.files["pcap"]
            if not file or not file.filename:
                return jsonify({"error": "No file was selected for upload."}), 400
                
            filename = secure_filename(file.filename)
            if not (filename.lower().endswith(".pcap") or filename.lower().endswith(".pcapng")):
                return jsonify({"error": "Invalid file type. Please upload a .pcap or .pcapng file."}), 400
                
            timestamp = int(time.time())
            save_filename = f"{timestamp}_{filename}"
            save_path = UPLOAD_DIR / save_filename
            
            file.save(str(save_path))
            return jsonify({
                "pcapPath": str(save_path),
                "filename": filename,
                "size": os.path.getsize(save_path)
            }), 201
        except Exception as e:
            app.logger.error(f"Upload error: {e}")
            return jsonify({"error": f"An unexpected error occurred while saving the file: {str(e)}"}), 500

    @app.route("/api/capture/stop", methods=["POST"])
    def capture_stop() -> Any:
        payload, stopped = manager.stop()
        return jsonify(payload), 200 if stopped else 409

    @app.route("/api/stream")
    def stream() -> Response:
        queue = manager.subscribe()

        def event_stream():
            try:
                yield sse_message("snapshot", manager.snapshot())
                while True:
                    try:
                        event_name, payload = queue.get(timeout=20)
                    except Empty:
                        yield ": keep-alive\n\n"
                        continue
                    yield sse_message(event_name, payload)
            finally:
                manager.unsubscribe(queue)

        response = Response(event_stream(), mimetype="text/event-stream")
        response.headers["Cache-Control"] = "no-cache"
        response.headers["X-Accel-Buffering"] = "no"
        return response

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False, threaded=True)
