import sqlite3

con = sqlite3.connect("results.db")
cur = con.cursor()

def setup_table():
    ### Creates the host table for enumeration if its not already made
    cur.execute("""
    CREATE TABLE IF NOT EXISTS hosts(
    host TEXT primary key,
    open_ports text,
    OS text,
    CVEs text, 
    URL text, 
    isAlive integer);
    """)
    con.commit()

    ### Creates the vulns table for storing found v ulns if its not already made
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vulns(
    id INTEGER primary key,
    host TEXT,
    type TEXT,
    severity TEXT,
    description TEXT,
    remediation TEXT);
    """)
    con.commit()

# Table is the table to insert into, data is a dicitionay of the format {"column":"value"}
# Adapted from: https://stackoverflow.com/questions/23374043/dynamically-creating-a-placeholder-to-insert-many-column-values-for-a-row-in-sql
def insert_to_table(table, data):

    placeholders = ', '.join(['?' for _ in range(len(data))])
    query = f"INSERT INTO {table} VALUES ({placeholders})"
    cur.execute(query, data)
    con.commit()

def read_table(table, item="*"):
    res = cur.execute(f"SELECT {item} FROM {table}")
    return (res.fetchall())

def read_table_by_key(table, key, keyValue, item="*"):
    res = cur.execute(f"""SELECT {item} FROM {table} 
    WHERE {key} = "{keyValue}"
    """)
    return (res.fetchall())

def read_column(item, key, keyValue, table="hosts"):
    res = cur.execute(f"""
    SELECT {item} from "{table}"
    WHERE {key} = "{keyValue}";
    """)
    return (res.fetchone())

def clear_table(table):
    cur.execute(f"""
    DELETE FROM {table}
    """)
    con.commit()

def update_table(table_name, key, keyValue, column1=None, value1=None, column2=None, value2=None, column3=None, value3=None):
    cur.execute(f"""
    UPDATE {table_name}
    SET {column1} = "{value1}"
    WHERE {key} = "{keyValue}";
    """)
    con.commit()

def check_if_exists(table_name, key, keyValue):
    res = cur.execute(f"""
    SELECT COUNT(1)
    FROM {table_name}
    WHERE {key} = "{keyValue}"
    """)
    if (res.fetchone()[0]) == 1:
        return True
    else:
        return False

