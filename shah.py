import re
import streamlit as st
import mysql.connector
from mysql.connector import Error
import hashlib
import pandas as pd


# Initialize session state variables if they don't exist
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'current_user' not in st.session_state:
    st.session_state['current_user'] = None

# Load the DataFrame globally
df = pd.read_csv("Business.csv")


# Function to connect to MySQL database
def connect_to_database():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='business',
            user='root',  # Update with your MySQL username
            password=''  # Update with your MySQL password
        )
        if connection.is_connected():
            return connection
    except Error as e:
        st.error(f"Error while connecting to MySQL: {e}")
        return None


# Function to hash a password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Function to validate email format
def is_valid_email(email):
    email_regex = r'^[a-z0-9._%+-]+@gmail\.com$'
    return re.match(email_regex, email) is not None


# Function to validate password format
def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True


# Function to register a new user
def register_user(email, password):
    try:
        connection = connect_to_database()
        if connection:
            cursor = connection.cursor()
            hashed_password = hash_password(password)  # Hash the password
            query = """
            INSERT INTO users (email, password)
            VALUES (%s, %s)
            """
            data = (email, hashed_password)
            cursor.execute(query, data)
            connection.commit()
            st.info(f"Registered user: {email}")  # Debug message
            return True
        else:
            st.error("Failed to connect to the database.")
    except Error as e:
        st.error(f"Error while registering user: {e}")
        return False
    finally:
        if connection:
            cursor.close()
            connection.close()


# Function to authenticate user login
def authenticate_user(email, password):
    try:
        connection = connect_to_database()
        if connection:
            cursor = connection.cursor()
            query = "SELECT * FROM users WHERE email = %s"
            data = (email,)
            cursor.execute(query, data)
            user = cursor.fetchone()
            if user:
                # Check if password matches
                hashed_password = hash_password(password)
                if user[2] == hashed_password:  # Assuming password is stored as hashed in the database
                    return user
            return None
    except Error as e:
        st.error(f"Error while authenticating user: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def login_register_page():
    st.title("Login/Register")
    option = st.radio("Select an option:", ["Login", "Register"])

    if option == "Login":
        email = st.text_input("Email:")
        password = st.text_input("Password:", type="password")
        if st.button("Login"):
            user = authenticate_user(email, password)
            if user:
                st.session_state['logged_in'] = True
                st.session_state['current_user'] = user
                st.success("Login Successful!")
                st.experimental_rerun()
            else:
                st.error("Login Failed. Please check your credentials.")

    elif option == "Register":
        email = st.text_input("Email:").strip().lower()
        password = st.text_input("Password:", type="password")
        confirm_password = st.text_input("Confirm Password:", type="password")


        if st.button("Register"):
            if not is_valid_email(email):
                st.error("Invalid email format. Please use a valid @gmail.com address in lowercase.")
            elif not is_valid_password(password):
                st.error(
                    "Password must be at least 8 characters long and include at least one special character and one digit.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            else:
                if register_user(email, password):
                    st.success("Registration Successful!")
                else:
                    st.error("Registration Failed. Please try again.")


# Logout function
def logout():
    st.session_state['logged_in'] = False
    st.session_state['current_user'] = None
    st.experimental_rerun()

# Page for Know Player
def Name():
    st.subheader("Product")
    player_names = df['Product_Name']
    selected_player = st.selectbox("Select a product:", player_names)
    selected_row = df[df['Product_Name'] == selected_player]

    if st.button("Show Product Data"):
        st.subheader(f"Product Details: {selected_player}")
        st.text(f"DP Price: {selected_row['DP Price'].values[0]}")
        st.text(f"MRP Price: {selected_row['MRP'].values[0]}")

    if st.button("Show Full Details"):
        st.write(selected_row)

def Code():
    st.subheader("Product")
    player_names = df['Product_Id']
    selected_player = st.selectbox("Select a Product:", player_names)
    selected_row = df[df['Product_Id'] == selected_player]

    if st.button("Show Product Data"):
        st.subheader(f"Product Details: {selected_player}")
        st.text(f"DP Price: {selected_row['DP Price'].values[0]}")
        st.text(f"MRP Price: {selected_row['MRP'].values[0]}")

    if st.button("Show Full Details"):
        st.write(selected_row)

# Main option page
def option_page():
    st.title("OPTIONS")
    option = st.radio("Choose an option:", ["Name", "Code", "LOGOUT"])


    if option == "Name":
        Name()
    elif option == "Code":
            Code()
    elif option == "LOGOUT":
        logout()

# Main function to run the app
def main():
    if st.session_state['logged_in']:
        option_page()
    else:
        login_register_page()


if __name__ == "__main__":
    main()

