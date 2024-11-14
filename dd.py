import streamlit as st
import duckdb
import bcrypt


# Initialize DuckDB connection
con = duckdb.connect("users.db")

username = "NAGA"

con.execute("DELETE FROM users WHERE username = ?", (username,))
con.commit()  # Commit the transaction to save changes


'''                       
def insert_user(username, password):
    try:
        con.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        con.commit()  # Commit the transaction to save changes
        return True
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

insert_user("NAGA", "BB")
'''
df = con.execute("SELECT * FROM users ").fetchdf()


print(df)
