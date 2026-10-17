"""Optional command line entry point; the GUI is the normal user entry."""
import argparse
import json
from pathlib import Path

from .core import ControllerError, Manager, detect_installation, profile


def main():
    parser = argparse.ArgumentParser(description="Codex 桌面版 重试控制器")
    parser.add_argument("action", choices=("status", "verify", "apply", "restore"))
    parser.add_argument("--exe", type=Path, help="实际的 codex.exe 路径；默认自动检测")
    parser.add_argument("--retries", default="1000")
    parser.add_argument("--interval", default="0.5", help="秒，最多三位小数")
    args = parser.parse_args()
    manager = None
    try:
        manager = Manager()
        path = args.exe or detect_installation()
        if args.action == "status":
            result = manager.inspect(path)
        elif args.action == "verify":
            result = manager.verify(path)
        elif args.action == "restore":
            result = manager.restore(path)
        else:
            result = manager.apply(path, profile(args.retries, args.interval))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ControllerError, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1
    finally:
        if manager is not None:
            manager.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
