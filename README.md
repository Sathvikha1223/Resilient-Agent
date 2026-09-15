# Resilient Agent

Resilient Agent is a host based ransomware detection and recovery system for Linux. It watches a directory in real time, looks for file activity patterns that match how ransomware behaves, and automatically keeps recovery points so that affected files can be restored without paying a ransom or losing data.
The detection logic is simple and explainable on purpose. Every alert can be traced back to a specific signal, like a burst of file rewrites or a jump in file entropy. Recovery is also human confirmed. The system never deletes files, overwrites files, or kills a process on its own. A person has to approve it.

## How it works

1. **Capture.** File system events are captured in real time using inotify, through the watchdog library.
2. **Attribution.** Every event is matched to the process that caused it. The system prefers the Linux audit subsystem, auditd, because it gives an authoritative process name and PID. If auditd isn't available, it falls back to a best effort guess using psutil.
3. **Detection.** Every five seconds, activity for each process is scored against three rules. A rate spike checks the modification rate against that process's own normal baseline. An extension change rule looks for bulk renames to unfamiliar extensions, like txt files turning into locked files. An entropy jump rule looks for file contents shifting toward random looking data, which is what encryption looks like. Already compressed formats like zip, jpg, and mp4 are excluded so they don't trigger false alarms.
4. **Baselining.** Normal behavior for each process is learned over time using a rolling average, so a process that's naturally busy doesn't get flagged just for being busy.
5. **Response.** If a process keeps triggering high risk scores, it gets escalated from a watch state to a critical state. At that point the system protects the most recent good snapshot so it can't be deleted, and writes an incident record.
6. **Recovery.** A person reviews the incident and has to type RESTORE to roll files back, or CONTAIN to stop the process. Nothing destructive happens automatically.

## Project structure

 File - What it does 

`events.py` - The shared event format used by both watcher backends 
`live_watcher.py` - Real time file watcher using watchdog, with a best effort guess at which process is responsible 
`auditd_watcher.py` - Reads auditd logs to get reliable process attribution 
`watcher_factory.py` - Picks auditd automatically if it's available, otherwise falls back 
`engine.py` - The core rule engine. Scores risk and writes plain language explanations 
`aggregator.py` - Turns raw events into per process activity windows, including entropy history 
`baseline_store.py` - Keeps a rolling baseline per process 
`recovery.py` - Handles snapshots, recovery readiness, and restoring files 
`incident_response.py` - The incident state machine that escalates from watch to critical 
`snapshot_manager.py` - Prunes old snapshots, but never deletes one tied to an active incident 
`containment.py` - Terminates a process, only when explicitly confirmed 
`confirm_restore.py` - The only script that actually restores files or kills a process. Always asks for confirmation first 
`live_main.py` - The main entry point that runs everything together 

## Requirements

This was built and tested on Ubuntu. You'll need Python 3, auditd for reliable process attribution, and a few Python packages.

bash
sudo apt update
sudo apt install -y python3 python3-pip auditd audispd-plugins
sudo systemctl enable --now auditd
sudo pip3 install watchdog psutil flask --break-system-packages


## Setup

Set up an audit rule so the sandbox folder gets watched with full process attribution.

```bash
sudo python3 live_main.py   # first run creates the sandbox folder, then press Ctrl+C
sudo auditctl -w $HOME/resilient_agent/sandbox -p wa -k resilient_agent
```

## Running it

**Terminal 1, start the watcher.**
bash
sudo python3 live_main.py

Check that it says it's using auditd for attribution. If it says it fell back to psutil, run `sudo auditctl -l` and make sure the rule above actually took.
<img width="1600" height="900" alt="image" src="https://github.com/user-attachments/assets/cf313204-e13e-4a0e-86b6-393f653200cc" />
<img width="1600" height="900" alt="image" src="https://github.com/user-attachments/assets/0abd90b5-bffb-4a96-9b09-7ccd90f5c2b3" />

**Terminal 2, simulate an attack.** This overwrites files in the sandbox with random bytes, renames them, then does it a second time to mimic a two stage encryption pass.
bash
sudo bash -c 'for f in sandbox/*.txt; do head -c 2000 /dev/urandom > "$f"; mv "$f" "${f%.txt}.locked"; done'
sleep 6
sudo bash -c 'for f in sandbox/*.locked; do head -c 2000 /dev/urandom > "$f.tmp"; mv "$f.tmp" "$f"; done'
<img width="1600" height="900" alt="image" src="https://github.com/user-attachments/assets/48e43d26-4c7f-4538-9bbc-f35bb2b205d4" />



**Terminal 3, once you see the incident declared message, confirm recovery.**
bash
sudo python3 confirm_restore.py

Type RESTORE to roll the sandbox back to the last protected snapshot.
<img width="1600" height="900" alt="image" src="https://github.com/user-attachments/assets/7b9d9b5a-0f94-4b72-b60f-79574161edf6" />


## Known limitations

Escalating to a critical incident currently requires the same process to show high risk scores in back to back windows. If an attack pauses briefly between writes, it can reset that count and delay the alert. A counter that decays slowly instead of resetting to zero would handle this better.

Process attribution happens at the level of the individual program, like mv or bash, rather than the parent session. So an attack that spans a few short lived processes isn't automatically treated as one continuous event.

The detection thresholds are fixed numbers that were tuned by hand, not learned or adaptive.

A browser based dashboard is planned but not built yet. Right now everything runs through the terminal.




