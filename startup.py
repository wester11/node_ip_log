"""Enrollment entry point used by install.sh.

The short-lived code is consumed once and is never written to disk.
"""

from __future__ import annotations

import os
import sys

from secure_channel import SecureChannelError, enroll_once


def main() -> int:
    try:
        result = enroll_once(
            os.getenv("VOID_NODE_ENROLLMENT_CODE", "").strip(),
            os.getenv("NODE_NAME", "").strip(),
        )
    except SecureChannelError as error:
        print(f"[VOID] ERROR: {error}", file=sys.stderr)
        return 1
    print(f"[VOID] Secure node enrolled: {result['node_name']} (id {result['node_id']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
