# Honeypot

A fake Telnet server that pretends to be a vulnerable smart router.
Every login attempt is logged: timestamp, attacker IP, username, password.

## How to run

1. `python honeypot.py` — starts the trap on port 2323
2. Open a **second** terminal: `python fake_attacker.py` — simulates a botnet
3. Watch the honeypot catch all 5 login attempts live
4. Press **Ctrl+C** in the honeypot window for the summary

The log file `honeypot.log` uses a pipe-separated format that the
log analyzer project reads next — that's the start of the home SIEM story.

## What I learned

- Honeypots: defense by deception — waste the attacker's time, learn their tricks
- The Mirai botnet did exactly this in reverse, hunting open Telnet worldwide
- Threaded socket servers: handling many attackers at once
- Logging in a machine-readable format so another tool can analyze it
- Why Telnet is dead: credentials fly across the network in plaintext

## Note

Only run this on your own machine. If you expose port 2323 to the
internet, real bots *will* find it within hours — fascinating, but save
that experiment for when you understand the risks.
