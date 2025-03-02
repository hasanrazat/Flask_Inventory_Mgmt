import sqlite3

# Connect to the database
db_path = "inventory.db"  # Update with the actual database path
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check if the 'description' column already exists
cursor.execute("PRAGMA table_info(assigned_inventory);")
columns = [row[1] for row in cursor.fetchall()]

# Add the 'description' column if it does not exist
if "description" not in columns:
    cursor.execute("ALTER TABLE assigned_inventory ADD COLUMN details TEXT;")
    print("Column 'details' added successfully.")
else:
    print("Column 'details' already exists.")

# Commit changes and close the connection
conn.commit()
conn.close()
