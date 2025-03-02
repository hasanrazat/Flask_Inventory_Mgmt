from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
import sqlite3
import csv
from fpdf import FPDF
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Ensure SQLite database connection
def get_db_connection():
    conn = sqlite3.connect('inventory.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT CHECK(role IN ("Owner", "Employee")) NOT NULL
            );

            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL,
                details TEXT, -- New column for extra item details
                quantity INTEGER NOT NULL,
                category TEXT,
                assigned_to INTEGER,
                status TEXT CHECK(status IN ('In Stock', 'Out of Stock', 'Issued', 'Remaining', 'Returned', 'Wasted')),
                date TEXT,
                FOREIGN KEY(assigned_to) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER,
                item_sold TEXT,
                quantity INTEGER,
                amount REAL,
                date TEXT,
                description TEXT,
                FOREIGN KEY(employee_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER,
                expense_type TEXT CHECK(expense_type IN ("General", "Work")),
                amount REAL,
                date TEXT,
                description TEXT,
                FOREIGN KEY(employee_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS assigned_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER,
                item_id INTEGER,
                item_name TEXT NOT NULL, -- New column to store item name
                details TEXT, -- New column to store item details
                quantity INTEGER NOT NULL,
                date TEXT DEFAULT CURRENT_DATE,
                FOREIGN KEY(employee_id) REFERENCES users(id),
                FOREIGN KEY(item_id) REFERENCES inventory(id)
            );

            CREATE TRIGGER IF NOT EXISTS update_inventory_status
            AFTER UPDATE OF quantity ON inventory
            BEGIN
                UPDATE inventory 
                SET status = CASE 
                    WHEN NEW.quantity > 0 THEN 'In Stock'
                    ELSE 'Out of Stock'
                END
                WHERE id = NEW.id;
            END;
        ''')
        conn.commit()


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/owner_signup", methods=["GET", "POST"])
def owner_signup():
    if request.method == "POST":
        name = request.form["name"]
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE role = 'Owner'")
            if cursor.fetchone():
                return "An Owner account already exists. Only one owner can register."

            cursor.execute("INSERT INTO users (name, role, username, password) VALUES (?, 'Owner', ?, ?)", 
                           (name, username, hashed_password))
            conn.commit()
        return redirect(url_for("login"))
    return render_template("owner_signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user["password"], password):  # Verify hashed password
                session["user_id"] = user["id"]
                session["role"] = user["role"]

                # Redirect to password change if first-time login (temporary password)
                if check_password_hash(user["password"], 'temporary123'):
                    flash('Please change your password before proceeding.', 'info')
                    return redirect(url_for('change_password'))

                if user["role"] == "Owner":
                    return redirect(url_for("owner_dashboard"))
                else:
                    return redirect(url_for("employee_dashboard"))

            else:
                return "<script>alert('Invalid Username or Password!'); window.history.back();</script>"

    return render_template("login.html")

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
        else:
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, session['user_id']))
                conn.commit()

            flash('Password changed successfully! Please log in again.', 'success')
            return redirect(url_for('login'))

    return render_template('change_password.html')

@app.route("/register_employee_popup", methods=["GET", "POST"])
def register_employee_popup():
    if request.method == "POST":
        if "user_id" not in session or session["role"] != "Owner":
            return redirect(url_for("login"))

        name = request.form["name"]
        username = request.form["username"]
        password = request.form["password"]

        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                return "<script>alert('Username already exists! Please choose another.'); window.history.back();</script>"

            # Hash the temporary password before storing
            hashed_password = generate_password_hash(password)

            # Insert new employee with hashed password
            cursor.execute("INSERT INTO users (name, role, username, password) VALUES (?, 'Employee', ?, ?)", 
                           (name, username, hashed_password))
            conn.commit()

        return '<script>alert("Employee Registered Successfully! They can log in with their temporary password."); window.close();</script>'

    return render_template("register_employee_popup.html")

@app.route('/register_employee', methods=['GET', 'POST'])
def register_employee():
    if 'user_id' not in session or session['role'] != 'Owner':
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = generate_password_hash('temporary123', method='sha256')  # Temporary password
        role = 'Employee'

        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)',
                               (name, username, password, role))
                conn.commit()
                flash('Employee registered successfully with a temporary password!', 'success')
            except sqlite3.IntegrityError:
                flash('Username already exists. Please choose another.', 'error')

    return render_template('register_employee.html')

@app.route("/owner_dashboard")
def owner_dashboard():
    if "user_id" not in session or session["role"] != "Owner":
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Fetch total inventory count
        cursor.execute("SELECT COUNT(*) FROM inventory")
        total_items = cursor.fetchone()[0]  

        # Fetch inventory overview
        cursor.execute("SELECT * FROM inventory")
        inventory = cursor.fetchall()

        # Fetch sales and expenses per employee
        cursor.execute("""
            SELECT users.id, users.name, 
                   COALESCE(SUM(expenses.amount), 0) AS total_expenses, 
                   COALESCE(SUM(sales.amount), 0) AS total_sales
            FROM users
            LEFT JOIN expenses ON users.id = expenses.employee_id
            LEFT JOIN sales ON users.id = sales.employee_id
            WHERE users.role = 'Employee'
            GROUP BY users.id
        """)
        employee_finances = cursor.fetchall()

        # Fetch assigned inventory details per employee
        cursor.execute("""
            SELECT assigned_inventory.employee_id, 
                   COUNT(assigned_inventory.item_id) AS assigned_items 
            FROM assigned_inventory
            GROUP BY assigned_inventory.employee_id
        """)
        assigned_inventory = {row[0]: row[1] for row in cursor.fetchall()}  # Convert to dict (employee_id -> item count)

        # Process employees for overview
        employees = []
        for row in employee_finances:
            employees.append({
                "id": row[0],       # Employee ID
                "name": row[1],     # Employee Name
                "expense": row[2],  # Total Expenses
                "sales": row[3],    # Total Sales
                "assigned_inventory": assigned_inventory.get(row[0], 0)  # Get assigned inventory count
            })

        # Fetch sales data for graph (last 7 days)
        cursor.execute("""
            SELECT DATE(date), SUM(amount) 
            FROM sales 
            WHERE date >= DATE('now', '-7 days') 
            GROUP BY DATE(date)
            ORDER BY date
        """)
        sales_data = cursor.fetchall()

        # Process sales data for Chart.js
        labels = [row[0] for row in sales_data]  # Extracting dates
        data = [row[1] for row in sales_data]    # Extracting sales amounts

    return render_template("owner_dashboard.html",
                           labels=labels if labels else [],
                           data=data if data else [],
                           total_items=total_items,
                           inventory=inventory,
                           employees=employees)




@app.route("/employee/dashboard", methods=["GET", "POST"])
def employee_dashboard():
    if "user_id" not in session or session["role"] != "Employee":
        return redirect(url_for("login"))

    user_id = session["user_id"]

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Fetch assigned inventory for the logged-in employee
        cursor.execute("SELECT id, item_name, quantity FROM inventory WHERE assigned_to = ?", (user_id,))
        inventory = cursor.fetchall()

        # Fetch logged sales and expenses
        cursor.execute("SELECT id, date, amount, description FROM sales WHERE employee_id = ?", (user_id,))
        sales = cursor.fetchall()

        cursor.execute("SELECT id, date, amount, description FROM expenses WHERE employee_id = ?", (user_id,))
        expenses = cursor.fetchall()

        if request.method == "POST":
            action = request.form.get("action")
            
            # Update inventory usage (Issued, Returned, Wasted)
            if action == "update_inventory":
                item_id = request.form["item_id"]
                update_type = request.form["update_type"]
                quantity = int(request.form["quantity"])

                # Adjust inventory quantity based on action
                if update_type == "Issued":
                    cursor.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ? AND assigned_to = ?", 
                                   (quantity, item_id, user_id))
                elif update_type == "Returned":
                    cursor.execute("UPDATE inventory SET quantity = quantity + ? WHERE id = ? AND assigned_to = ?", 
                                   (quantity, item_id, user_id))
                elif update_type == "Wasted":
                    cursor.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ? AND assigned_to = ?", 
                                   (quantity, item_id, user_id))

                conn.commit()

            # Log daily sales
            elif action == "log_sales":
                amount = request.form["amount"]
                description = request.form["description"]

                cursor.execute("INSERT INTO sales (employee_id, date, amount, description) VALUES (?, DATE('now'), ?, ?)", 
                               (user_id, amount, description))
                conn.commit()

            # Log daily expenses
            elif action == "log_expenses":
                amount = request.form["amount"]
                description = request.form["description"]

                cursor.execute("INSERT INTO expenses (employee_id, date, amount, description) VALUES (?, DATE('now'), ?, ?)", 
                               (user_id, amount, description))
                conn.commit()
                

            return redirect(url_for("employee_dashboard"))

    return render_template("employee_dashboard.html", inventory=inventory, sales=sales, expenses=expenses)

@app.route("/personal_info")
def personal_info():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, username FROM users WHERE id = ?", (session["user_id"],))
        owner = cursor.fetchone()

    return render_template("personal_info.html", owner={"name": owner["name"], "username": owner["username"]})
@app.route("/employee_info")
def employee_info():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, username FROM users WHERE id = ?", (session["user_id"],))
        employee = cursor.fetchone()

    if employee is None:
        flash("Employee not found", "error")
        return redirect(url_for("dashboard"))

    owner = {"name": employee[0], "username": employee[1]}  # Define `owner`

    return render_template("employee_info.html", owner=owner)  # Pass `owner`
    
@app.route("/inventory", methods=["GET"])
def inventory():
    if "user_id" not in session or session["role"] != "Owner":
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, item_name, quantity, category, status, date 
            FROM inventory 
            ORDER BY id DESC
        """)
        inventory_items = cursor.fetchall()
        # Debug print
        print(f"Found {len(inventory_items)} inventory items")

    return render_template("inventory.html", inventory=inventory_items)

@app.route("/add_inventory", methods=["POST"])
def add_inventory():
    if "user_id" not in session or session["role"] != "Owner":
        return redirect(url_for("login"))

    item_name = request.form["item_name"]
    quantity = request.form["quantity"]
    category = request.form["category"]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO inventory (item_name, quantity, category, status, date) VALUES (?, ?, ?, 'Remaining', DATE('now'))", 
                       (item_name, quantity, category))
        conn.commit()

    return redirect(url_for("inventory"))

@app.route("/update_inventory/<int:item_id>", methods=["GET", "POST"])
def update_inventory(item_id):
    if "user_id" not in session or session["role"] != "Owner":
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if request.method == "POST":
            item_name = request.form.get("item_name")
            quantity = int(request.form.get("quantity", 0))
            category = request.form.get("category")
            
            # Debug print
            print(f"Updating item {item_id}: name={item_name}, quantity={quantity}, category={category}")
            
            # Input validation
            if not all([item_name, category]):
                flash("All fields are required!", "error")
                return redirect(url_for("inventory"))
                
            # Update the inventory item with status
            status = "In Stock" if quantity > 0 else "Out of Stock"
            cursor.execute("""
                UPDATE inventory 
                SET item_name = ?, quantity = ?, category = ?, status = ?
                WHERE id = ?
            """, (item_name, quantity, category, status, item_id))
            
            if cursor.rowcount > 0:
                conn.commit()
                flash("Inventory updated successfully!", "success")
            else:
                flash("Failed to update inventory. Item not found.", "error")
                
            return redirect(url_for("inventory"))

        cursor.execute("SELECT * FROM inventory WHERE id = ?", (item_id,))
        item = cursor.fetchone()

    return render_template("update_inventory.html", item=item)

@app.route("/delete_inventory/<int:item_id>", methods=["POST"])
def delete_inventory(item_id):
    if "user_id" not in session or session["role"] != "Owner":
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM inventory WHERE id = ?", (item_id,))
        conn.commit()

    flash("Inventory item deleted successfully!", "success")
    return redirect(url_for("inventory"))

@app.route("/out_inventory")
def out_inventory():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM inventory WHERE quantity > 0")
        inventory = cursor.fetchall()
        
        cursor.execute("SELECT id, name FROM users WHERE role = 'Employee'")
        employees = cursor.fetchall()

    return render_template("out_inventory.html", inventory=inventory, employees=employees)

@app.route("/assign_inventory", methods=["POST"])
def assign_inventory():
    if "user_id" not in session or session["role"] != "Owner":
        return redirect(url_for("login"))

    employee_id = request.form["employee_id"]
    item_id = request.form["item_id"]
    quantity = int(request.form["quantity"])

    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Ensure inventory exists and has enough stock
        cursor.execute("SELECT quantity FROM inventory WHERE id = ?", (item_id,))
        current_quantity = cursor.fetchone()[0]

        if current_quantity < quantity:
            flash("Not enough stock available!", "error")
            return redirect(url_for("inventory"))

        # Deduct from main stock and assign to employee
        new_quantity = current_quantity - quantity
        cursor.execute("UPDATE inventory SET quantity = ? WHERE id = ?", (new_quantity, item_id))
        
        # Assign inventory to employee
        cursor.execute("INSERT INTO assigned_inventory (employee_id, item_id, quantity, date) VALUES (?, ?, ?, DATE('now'))",
                       (employee_id, item_id, quantity))
        
        conn.commit()
    return '<script>alert("Inventory Assigned Successfully!"); window.close();</script>'

@app.route("/sales", methods=["GET"])
def sales():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.id, s.employee_id, s.item_sold, s.quantity, s.amount, s.date, u.name 
            FROM sales s
            LEFT JOIN users u ON s.employee_id = u.id
            ORDER BY s.date DESC
        """)
        sales = cursor.fetchall()

    return render_template("sales.html", sales=sales)

@app.route("/add_sale", methods=["POST"])
def add_sale():
    if "user_id" not in session or session["role"] != "Employee":
        return redirect(url_for("login"))  # Ensure only employees access this route

    item = request.form["item"]
    quantity = request.form["quantity"]
    amount = request.form["amount"]
    employee_id = session["user_id"]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO sales (employee_id, item_sold, quantity, amount, date) VALUES (?, ?, ?, ?, DATE('now'))", 
                       (employee_id, item, quantity, amount))
        conn.commit()

    return redirect(url_for("my_sales"))  # Redirect to Employee's My Sales Page


@app.route('/expenses', methods=['GET', 'POST'])
def expenses():
    if "user_id" not in session or session["role"] != "Owner":
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Join with users table to get employee names
        cursor.execute("""
            SELECT e.id, e.employee_id, e.expense_type, e.amount, e.date, e.description, u.name 
            FROM expenses e
            LEFT JOIN users u ON e.employee_id = u.id
            ORDER BY e.date DESC
        """)
        expenses = cursor.fetchall()

    return render_template('expenses.html', expenses=expenses)

@app.route("/add_owner_expense", methods=["POST"])
def add_owner_expense():
    if "user_id" not in session or session["role"] != "Owner":
        return redirect(url_for("login"))

    expense_type = request.form.get("expense_type", "").strip()
    amount = request.form.get("amount", "").strip()
    description = request.form.get("description", "").strip()

    if expense_type not in ["General", "Work"]:
        flash("Invalid Expense Type! Choose 'General' or 'Work'.", "error")
        return redirect(url_for("expenses"))

    if not expense_type or not amount or not description:
        flash("All fields are required!", "error")
        return redirect(url_for("expenses"))

    owner_id = session["user_id"]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO expenses (employee_id, expense_type, amount, date, description) VALUES (?, ?, ?, DATE('now'), ?)",
            (owner_id, expense_type, amount, description)
        )
        conn.commit()

    flash("Expense recorded successfully!", "success")
    return redirect(url_for("expenses"))


@app.route("/add_expense", methods=["POST"])
def add_expense():
    if "user_id" not in session or session["role"] != "Employee":
        return redirect(url_for("login"))

    expense_type = request.form.get("expense_type", "").strip()
    amount = request.form.get("amount", "").strip()
    description = request.form.get("description", "").strip()

    # Validate that expense_type is either 'General' or 'Work'
    if expense_type not in ["General", "Work"]:
        flash("Invalid Expense Type! Choose 'General' or 'Work'.", "error")
        return redirect(url_for("my_expenses"))

    if not expense_type or not amount or not description:
        flash("All fields are required!", "error")
        return redirect(url_for("my_expenses"))

    employee_id = session["user_id"]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO expenses (employee_id, expense_type, amount, date, description) VALUES (?, ?, ?, DATE('now'), ?)",
            (employee_id, expense_type, amount, description)
        )
        conn.commit()

    flash("Expense recorded successfully!", "success")
    return redirect(url_for("my_expenses"))



@app.route("/records")
def records():
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Get sales with employee names
        cursor.execute("""
            SELECT s.*, u.name as employee_name
            FROM sales s
            LEFT JOIN users u ON s.employee_id = u.id
            ORDER BY s.date DESC
        """)
        sales = cursor.fetchall()
        
        # Get expenses with employee names
        cursor.execute("""
            SELECT e.*, u.name as employee_name
            FROM expenses e
            LEFT JOIN users u ON e.employee_id = u.id
            ORDER BY e.date DESC
        """)
        expenses = cursor.fetchall()
        
        # Get inventory records
        cursor.execute("SELECT * FROM inventory ORDER BY date DESC")
        inventory = cursor.fetchall()
        
    return render_template("records.html", 
                         sales=sales, 
                         expenses=expenses, 
                         inventory=inventory)

# Export Sales to CSV
@app.route("/export_sales_csv")
def export_sales_csv():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.id, s.employee_id, s.item_sold, s.quantity, s.amount, s.date, u.name 
            FROM sales s
            LEFT JOIN users u ON s.employee_id = u.id
            ORDER BY s.id ASC
        """)
        sales = cursor.fetchall()

    output = "ID,Employee Name,Item Sold,Quantity,Amount,Date\n"
    for sale in sales:
        row = [
            str(sale[0]),                    # ID
            sale[6] if sale[6] else 'Owner', # Employee Name
            sale[2],                         # Item Sold
            str(sale[3]),                    # Quantity
            str(sale[4]),                    # Amount
            str(sale[5])                     # Date
        ]
        output += ",".join(row) + "\n"

    response = Response(output)
    response.headers["Content-Disposition"] = "attachment; filename=sales.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

# Export Sales to PDF
@app.route("/export_sales_pdf")
def export_sales_pdf():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sales")
        sales = cursor.fetchall()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Sales Report", ln=True, align="C")

    pdf.cell(40, 10, txt="ID", border=1)
    pdf.cell(40, 10, txt="Employee ID", border=1)
    pdf.cell(40, 10, txt="Item", border=1)
    pdf.cell(30, 10, txt="Quantity", border=1)
    pdf.cell(30, 10, txt="Amount", border=1)
    pdf.ln()

    for sale in sales:
        pdf.cell(40, 10, txt=str(sale[0]), border=1)
        pdf.cell(40, 10, txt=str(sale[1]), border=1)
        pdf.cell(40, 10, txt=sale[2], border=1)
        pdf.cell(30, 10, txt=str(sale[3]), border=1)
        pdf.cell(30, 10, txt=str(sale[4]), border=1)
        pdf.ln()

    response = Response(pdf.output(dest="S").encode("latin1"))
    response.headers["Content-Disposition"] = "attachment; filename=sales.pdf"
    response.headers["Content-Type"] = "application/pdf"
    return response

# Export Expenses to CSV
@app.route("/export_expenses_csv")
def export_expenses_csv():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.id, e.employee_id, e.expense_type, e.amount, e.date, e.description, u.name 
            FROM expenses e
            LEFT JOIN users u ON e.employee_id = u.id
            ORDER BY e.id ASC
        """)
        expenses = cursor.fetchall()

    output = "ID,Employee Name,Expense Type,Amount,Date,Description\n"
    for expense in expenses:
        # Handle NULL values by converting them to empty strings
        row = [
            str(expense[0] or ''),                    # ID
            str(expense[6] or 'Owner'),              # Employee Name
            str(expense[2] or 'General'),            # Expense Type
            str(expense[3] or '0'),                  # Amount
            str(expense[4] or ''),                   # Date
            f'"{str(expense[5] or "")}"'            # Description
        ]
        output += ",".join(row) + "\n"

    response = Response(output)
    response.headers["Content-Disposition"] = "attachment; filename=expenses.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

# Export Inventory to CSV
@app.route("/export_inventory_csv")
def export_inventory_csv():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, item_name, quantity, category, status, date 
            FROM inventory 
            ORDER BY id ASC
        """)
        inventory = cursor.fetchall()

    output = "ID,Item Name,Quantity,Category,Status,Date\n"
    for item in inventory:
        # Handle NULL values and ensure proper string formatting
        row = [
            str(item[0]),                    # ID
            str(item[1] or ''),             # Item Name
            str(item[2] or '0'),            # Quantity
            str(item[3] or ''),             # Category
            str(item[4] or 'Unknown'),      # Status
            str(item[5] or '')              # Date
        ]
        output += ",".join(row) + "\n"

    response = Response(output)
    response.headers["Content-Disposition"] = "attachment; filename=inventory.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

@app.route('/my_sales')
def my_sales():
    if "user_id" not in session or session["role"] != "Employee":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sales WHERE employee_id = ?", (user_id,))
        sales = cursor.fetchall()

    return render_template('my_sales.html', sales=sales)



@app.route("/assigned_inventory")
def assigned_inventory():
    if "user_id" not in session or session["role"] != "Employee":
        return redirect(url_for("login"))

    user_id = session["user_id"]  # Get logged-in employee ID

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT inventory.item_name, assigned_inventory.quantity, 
                   inventory.category, inventory.status, assigned_inventory.date
            FROM assigned_inventory
            JOIN inventory ON assigned_inventory.item_id = inventory.id
            WHERE assigned_inventory.employee_id = ?
        """, (user_id,))
        inventory_items = cursor.fetchall()

        print("DEBUG: Assigned Inventory Items:", inventory_items)  # <-- Check output in terminal

    return render_template("assigned_inventory.html", inventory=inventory_items)




@app.route('/my_expenses')
def my_expenses():
    if "user_id" not in session or session["role"] != "Employee":
        return redirect(url_for("login"))

    employee_id = session["user_id"]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, employee_id, expense_type, amount, date, description FROM expenses WHERE employee_id = ? ORDER BY date DESC",
            (employee_id,)
        )
        expenses = cursor.fetchall()

    return render_template("my_expenses.html", my_expenses=expenses)  # Fix: Passing the correct variable




@app.route("/logout")
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for("login"))  # Redirect to login page

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
