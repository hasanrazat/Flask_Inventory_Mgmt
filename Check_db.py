import sqlite3

def list_existing_tables():
    conn = sqlite3.connect("inventory.db")  # Replace with your actual database file
    cursor = conn.cursor()

    # Fetch all table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]

    conn.close()

    if tables:
        print("📋 Available Tables in Database:")
        for table in tables:
            print(f" - {table}")
    else:
        print("⚠️ No tables found in the database.")

# Run the function to list tables
list_existing_tables()
