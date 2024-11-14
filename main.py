import streamlit as st
import duckdb
import bcrypt

# Initialize DuckDB connection
con = duckdb.connect("users.db")

# Create the users table if it doesn't exist
con.execute("""
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR PRIMARY KEY,
    password VARCHAR
)
""")

# Helper function to add a new user
def add_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    con.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))

# Helper function to verify user credentials
def verify_user(username, password):
    try:
        result = con.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
        if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
            return True
        return False
    except:
        return False

# Signup form
def signup():
    st.title("Sign Up")
    username = st.text_input("Enter a username")
    password = st.text_input("Enter a password", type="password")
    confirm_password = st.text_input("Confirm password", type="password")

    if st.button("Sign Up"):
        if password != confirm_password:
            st.error("Passwords do not match!")
        else:
            try:
                add_user(username, password)
                st.success("User signed up successfully! You can now log in.")
            except Exception as e:
                st.error(f"Signup failed: {e}")

# Login form
def login():
    st.title("Login")
    username = st.text_input("Enter your username")
    password = st.text_input("Enter your password", type="password")

    if st.button("Login"):
        if verify_user(username, password):
            st.success("Logged in successfully!")
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
        else:
            st.error("Invalid username or password!")

# Logout function
def logout():
    if st.button("Logout"):
        st.session_state["logged_in"] = False
        st.session_state["username"] = None
        st.success("Logged out successfully.")

# Main app logic
def main():
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False

    if st.session_state["logged_in"]:
        st.write(f"Welcome, {st.session_state['username']}!")
        logout()
    else:
        option = st.sidebar.selectbox("Choose Action", ["Login", "Sign Up"])

        if option == "Login":
            login()
        else:
            signup()

if __name__ == "__main__":
    main()
