import sqlite3
con = sqlite3.connect("test.db")
cur = con.cursor()


def insert_to_table(table, value1, value2=None, value3=None):
    cur.execute(f"""
        INSERT INTO {table} VALUES
        ("{value1}","{value2}","{value3}")
                """)

    con.commit()



def read_table(table, item="*"):
    res = cur.execute(f"SELECT {item} FROM {table}")
    return (res.fetchall())

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