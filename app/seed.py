from app.main import get_db, create_a_table, hash_password

create_a_table()

db = get_db()

for i in range(1,21):

    email = f"user{i}@email.com"

    username = f"user{i}"

    hashed_pw = hash_password(f"fast-pass-{i}!")

    db.execute("INSERT OR IGNORE INTO users VALUES (?,?,?)", (email, username, hashed_pw))

db.execute("INSERT OR IGNORE INTO users VALUES (?,?,?)", ("weakuser@email.com", "weakuser", hash_password("welcome4")))

db.commit()

db.close()

print("db seeded!")