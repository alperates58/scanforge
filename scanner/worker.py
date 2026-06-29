import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


def bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def main() -> None:
    output_path = Path(os.getenv("SCANNER_MOCK_OUTPUT", "/data/mock-scan-result.json"))
    heartbeat_seconds = int(os.getenv("SCANNER_HEARTBEAT_SECONDS", "30"))
    allow_unverified = bool_env("ALLOW_UNVERIFIED_DOMAINS", False)
    safe_mode = bool_env("SCAN_SAFE_MODE", True)

    with Path("mock_scan_result.json").open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    payload["generated_at"] = datetime.now(timezone.utc).isoformat()
    payload["safety_profile"] = {
        "mock_worker": True,
        "safe_mode": safe_mode,
        "allow_unverified_domains": allow_unverified,
        "external_tools_executed": [],
        "network_scanning_enabled": False,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(
        json.dumps(
            {
                "service": "scanforge-mock-scanner",
                "status": "ready",
                "output": str(output_path),
                "safe_mode": safe_mode,
                "allow_unverified_domains": allow_unverified,
                "external_tools_executed": [],
            }
        ),
        flush=True,
    )

    while True:
        print(
            json.dumps(
                {
                    "service": "scanforge-mock-scanner",
                    "status": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            flush=True,
        )
        time.sleep(heartbeat_seconds)


if __name__ == "__main__":
    main()
