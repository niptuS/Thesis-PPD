import sys

from design.Menu import run_menu, SECTIONS


def action_handler(section_key: str, action: str):

    routing = {
        "home":      "Home dashboard",
        "scenario":  "Scenario Editor module",
        "devices":   "Devices module",
        "benign":    "Benign Profiles module",
        "attacks":   "Attack Library module",
        "timeline":  "Timeline module",
        "live":      "Live Execution module",
        "logs":      "Logs module",
        "artifacts": "Artifacts module",
        "help":      "Help module",
    }

    target = routing.get(section_key, "Unknown section")

    if action == "ctrl_s":
        print(f"[ACTION] Save scenario (global)")
    elif action == "ctrl_r":
        print(f"[ACTION] Start/resume execution (global)")
    elif action == "ctrl_p":
        print(f"[ACTION] Pause execution (global)")
    elif action == "ctrl_x":
        print(f"[ACTION] Abort scenario (global)")
    elif action == "ctrl_l":
        print(f"[ACTION] Jump to logs (global)")
    else:
        print(f"[ACTION] {target} → {action}")


def main():
    print("Starting SH-DATASET Orchestrator...")
    print("Press Ctrl+C in the terminal to force-quit if needed.\n")

    try:
        app = run_menu(action_callback=action_handler)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nSession ended. Final status: {app.status}, capture: {app.capture}")


if __name__ == "__main__":
    main()