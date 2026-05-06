import MySQLdb

# Database connection settings from your settings.py
DB_SETTINGS = {
    'host': '127.0.0.1',
    'user': 'ninecom',
    'passwd': 'ninecom@1237',
    'db': 'radius_db',
    'port': 3306
}

def fix_database():
    try:
        print("Connecting to database...")
        db = MySQLdb.connect(**DB_SETTINGS)
        cursor = db.cursor()
        
        print("Adding 'router_ip' column to 'pending_users' table...")
        # Check if column exists first to avoid error if already added
        cursor.execute("SHOW COLUMNS FROM pending_users LIKE 'router_ip'")
        result = cursor.fetchone()
        
        if result:
            print("Column 'router_ip' already exists!")
        else:
            cursor.execute("ALTER TABLE pending_users ADD COLUMN router_ip VARCHAR(50) NULL;")
            db.commit()
            print("Successfully added column 'router_ip'!")
            
        db.close()
        print("\nAll done! You can now refresh your browser.")
        
    except Exception as e:
        print(f"\nError: {e}")
        print("Make sure your MySQL server is running and the credentials are correct.")

if __name__ == "__main__":
    fix_database()
