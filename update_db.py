import sqlite3

def update_database():
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()

    cursor.executescript('''
        PRAGMA foreign_keys=off;
        BEGIN TRANSACTION;

        -- Rename the existing inventory table
        ALTER TABLE inventory RENAME TO old_inventory;

        -- Create a new inventory table with the updated CHECK constraint
        CREATE TABLE inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            category TEXT,
            assigned_to INTEGER,
            status TEXT CHECK(status IN ('In Stock', 'Out of Stock', 'Issued', 'Remaining', 'Returned', 'Wasted')),
            date TEXT,
            FOREIGN KEY(assigned_to) REFERENCES users(id)
        );

        -- Copy data from the old inventory table to the new one (excluding 'details' if it does not exist)
        INSERT INTO inventory (id, item_name, quantity, category, assigned_to, status, date)
        SELECT id, item_name, quantity, category, assigned_to, status, date FROM old_inventory;

        -- Drop the old inventory table
        DROP TABLE old_inventory;

        COMMIT;
        PRAGMA foreign_keys=on;
    ''')

    # Update existing records if necessary
    cursor.execute("""
        UPDATE inventory
        SET status = CASE 
            WHEN status = 'Remaining' THEN 'In Stock'
            WHEN status = 'Issued' THEN 'Out of Stock'
            ELSE status
        END
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    update_database()
    print("Database schema updated successfully.")
