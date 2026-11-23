"""
Admin CLI - run on the coordinator host.

  python admin.py add-admin ops                      # dashboard login (prompts for password)
  # Create user accounts and scoped bearer tokens from the admin dashboard.
  python admin.py add-agent LAPTOP-0142 --owner "Emp_A" --label "Chennai"   # owner=user, label=location
  python admin.py rotate-agent LAPTOP-0142
  python admin.py disable-agent LAPTOP-0142  |  enable-agent ...
  python admin.py list-agents  |  list-clients (legacy tokens are disabled)
  python admin.py set-latest-agent-version 2.3.1
  python admin.py add-office-ip 203.0.113.10 --label "Chennai office"     # single IP
  python admin.py add-office-ip 198.51.100.0/28 --label "Corporate VPN"   # or a range
  python admin.py remove-office-ip 203.0.113.10
  python admin.py list-office-ips

Disabling an agent and office-IP changes take effect on the running coordinator within ~15 seconds.
"""
import argparse
import getpass
import re
import sqlite3
import sys

from store import Store

AGENT_VERSION_PATTERN = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")


def main():
    p = argparse.ArgumentParser(description="Fetch coordinator admin")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add-agent"); a.add_argument("agent_id"); a.add_argument("--label", default=""); a.add_argument("--owner", default=""); a.add_argument("--token", default="")
    for name in ("rotate-agent", "disable-agent", "enable-agent"):
        sub.add_parser(name).add_argument("agent_id")
    sub.add_parser("add-admin").add_argument("username")
    sub.add_parser("delete-agent").add_argument("agent_id")
    sub.add_parser("list-agents"); sub.add_parser("list-clients")
    sub.add_parser("set-latest-agent-version").add_argument("version")
    o = sub.add_parser("add-office-ip", help="office/VPN egress IP or CIDR range; agents exiting here are skipped")
    o.add_argument("network"); o.add_argument("--label", default="")
    sub.add_parser("remove-office-ip").add_argument("network")
    sub.add_parser("list-office-ips")
    t = sub.add_parser("update-token-by-agent"); t.add_argument("agent_id"); t.add_argument("--token")
    args = p.parse_args()
    s = Store()

    try:
        if args.cmd == "add-agent":
            # print(f"Token : {args.token}")
            tok = s.add_agent(args.agent_id, args.label, args.owner, args.token)
            print(f"Agent '{args.agent_id}' registered.\nAGENT TOKEN (shown once): {tok}")
        elif args.cmd == "delete-agent":
            ok = s.delete_agent(args.agent_id)
            print("done" if ok else "no such agent")
        elif args.cmd == "rotate-agent":
            tok = s.rotate_agent_token(args.agent_id)
            print(f"New AGENT TOKEN (shown once): {tok}" if tok else "no such agent")
        elif args.cmd in ("disable-agent", "enable-agent"):
            ok = s.set_agent_enabled(args.agent_id, args.cmd == "enable-agent")
            print("done" if ok else "no such agent")
        elif args.cmd == "add-admin":
            pw = getpass.getpass("Password: ")
            if len(pw) < 12 or pw != getpass.getpass("Repeat: "):
                sys.exit("Passwords must match and be at least 12 characters.")
            s.set_admin(args.username, pw)
            print(f"Admin '{args.username}' saved.")
        elif args.cmd == "list-agents":
            for r in s.list_agents():
                print(f"{r['agent_id']:<20} enabled={r['enabled']} owner={r['owner']:<15} "
                      f"last_seen={r['last_seen']} egress={r['egress_ip']} token_hash={r['token_hash']} encrypted_token={r['encrypted_token']}")
        elif args.cmd == "set-latest-agent-version":
            if len(args.version) > 64 or not AGENT_VERSION_PATTERN.fullmatch(args.version):
                sys.exit("Agent version must use MAJOR.MINOR.PATCH (for example 2.3.1), up to 64 characters.")
            s.set_latest_agent_version(args.version)
            print(f"Latest agent version set to {args.version}.")
        elif args.cmd == "list-clients":
            for r in s.list_clients():
                print(f"{r['client_id']:<20} enabled={r['enabled']} requests={r['requests']} last_used={r['last_used']}")
        elif args.cmd == "add-office-ip":
            cidr = s.add_office_network(args.network, args.label)
            print(f"Office network {cidr} added.")
        elif args.cmd == "remove-office-ip":
            print("removed" if s.remove_office_network(args.network) else "not found")
        elif args.cmd == "update-token-by-agent":
            tok = s.update_token_by_agent(args.agent_id, args.token)
            print(f"New AGENT TOKEN (shown once): {tok}" if tok else "no such agent")
        elif args.cmd == "list-office-ips":
            rows = s.list_office_networks()
            if not rows:
                print("No office networks configured.")
            for r in rows:
                print(f"{r['cidr']:<22} {r['label']}")
    except ValueError as e:
        sys.exit(f"Not a valid IP address or CIDR range: {e}")
    except sqlite3.IntegrityError as e:
        sys.exit(f"Already exists: {e}")


if __name__ == "__main__":
    main()
