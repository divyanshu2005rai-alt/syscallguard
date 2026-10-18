<!--
  demo-runbook.md: step-by-step stage runbook.
  Tracks: D + P (co-owned)
  Contract: commands from AGENTS.md "How to run each component"; topology from ARCHITECTURE.md.

  TODO (M7 Freeze):
    - VM snapshot restore, firewall ports, start order (guard | bridge, internal_api, attacker, dashboard)
    - exact agent.py commands per scene, with demo/reset.sh between scenes
    - fallbacks: browser renderer if Electron breaks; backup video (Suyash records, Azaan verifies)
    - rule: never edit demo/project/.env while the guard is running (an editor save can change its inode
      and silently end protection); if you do, restart the guard
    - 3 consecutive cold runs logged
-->
