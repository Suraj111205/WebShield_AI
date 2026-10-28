"""
WebShield AI - User Management Utility
Use this script to view, add, or delete users directly from your terminal.

Usage:
    python manage_users.py list
    python manage_users.py delete <email_or_id>
    python manage_users.py add <email> <password> [name]
    python manage_users.py delete-all
"""

import sys
from app.database import SessionLocal, User, UserSession, ScanLog, hash_password, validate_email_address


def list_users():
    """Print all registered users in a formatted table."""
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.id.asc()).all()
        if not users:
            print("\n[i] No users found in database.\n")
            return

        print("\n" + "=" * 78)
        print(f"{'ID':<5} | {'NAME':<20} | {'EMAIL':<30} | {'SCANS':<6}")
        print("=" * 78)
        for u in users:
            print(f"{u.id:<5} | {u.name[:20]:<20} | {u.email[:30]:<30} | {u.scan_count:<6}")
        print("=" * 78)
        print(f"Total Users: {len(users)}\n")
    finally:
        db.close()


def delete_user(identifier: str):
    """Delete a user by email address or ID."""
    if not identifier:
        print("[!] Please specify an email or user ID to delete.")
        return

    db = SessionLocal()
    try:
        query = db.query(User)
        if identifier.isdigit():
            user = query.filter(User.id == int(identifier)).first()
        else:
            user = query.filter(User.email == identifier.strip().lower()).first()

        if not user:
            print(f"[!] No user found matching: '{identifier}'")
            return

        user_id = user.id
        email = user.email
        name = user.name

        # Delete associated sessions & update scan logs
        db.query(UserSession).filter(UserSession.user_id == user_id).delete()
        db.query(ScanLog).filter(ScanLog.user_id == user_id).update({ScanLog.user_id: None})
        db.delete(user)
        db.commit()

        print(f"[OK] Successfully deleted user ID {user_id} ('{name}', {email}) from database.")
    except Exception as e:
        db.rollback()
        print(f"[!] Error deleting user: {e}")
    finally:
        db.close()


def add_user(email: str, password: str, name: str = ""):
    """Create a new user directly from CLI."""
    valid, err = validate_email_address(email)
    if not valid:
        print(f"[!] Invalid email: {err}")
        return

    if len(password) < 6:
        print("[!] Password must be at least 6 characters.")
        return

    db = SessionLocal()
    try:
        email_clean = email.strip().lower()
        existing = db.query(User).filter(User.email == email_clean).first()
        if existing:
            print(f"[!] An account with email '{email_clean}' already exists (ID: {existing.id}).")
            return

        user = User(
            name=name.strip() or email_clean.split("@")[0].capitalize(),
            email=email_clean,
            password_hash=hash_password(password),
            scan_count=0
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"[OK] Created user: ID={user.id}, Name='{user.name}', Email='{user.email}'")
    finally:
        db.close()


def delete_all_users():
    """Delete all registered users."""
    confirm = input("Are you sure you want to delete ALL users? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[i] Operation cancelled.")
        return

    db = SessionLocal()
    try:
        db.query(UserSession).delete()
        count = db.query(User).delete()
        db.commit()
        print(f"[OK] Successfully deleted {count} user(s).")
    finally:
        db.close()


def print_help():
    print("""
WebShield AI User Manager
=========================
Commands:
  python manage_users.py list
      View all registered users and their scan stats

  python manage_users.py delete <email_or_id>
      Delete a specific user (e.g. python manage_users.py delete user@example.com)

  python manage_users.py add <email> <password> [name]
      Manually register a user

  python manage_users.py delete-all
      Delete all registered users
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        list_users()
        print_help()
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "list":
        list_users()
    elif cmd == "delete":
        if len(sys.argv) < 3:
            print("[!] Please provide an email or ID. Example: python manage_users.py delete user@gmail.com")
        else:
            delete_user(sys.argv[2])
    elif cmd == "add":
        if len(sys.argv) < 4:
            print("[!] Example: python manage_users.py add user@test.com Password123 \"John Doe\"")
        else:
            name_val = sys.argv[4] if len(sys.argv) >= 5 else ""
            add_user(sys.argv[2], sys.argv[3], name_val)
    elif cmd == "delete-all":
        delete_all_users()
    else:
        print_help()
