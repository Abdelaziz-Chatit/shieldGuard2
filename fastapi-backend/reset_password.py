# reset_password.py
import sys
from app import SessionLocal, User, hash_password

if len(sys.argv) != 3:
    print("Usage: python reset_password.py <username> <new_password>")
    sys.exit(1)

username = sys.argv[1]
new_password = sys.argv[2]

db = SessionLocal()
try:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        print("User not found")
        sys.exit(1)
    user.password_hash = hash_password(new_password)
    db.commit()
    print(f"Password for {username} has been updated.")
finally:
    db.close()