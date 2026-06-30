with open("server_logs.txt", "a") as f:
    for i in range(500):
        f.write(f"2026-06-30 15:10:{i:02d} WARNING Unauthorized API scanning attempt from IP 10.0.0.1\n")