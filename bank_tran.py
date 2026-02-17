import streamlit as st
import sqlite3
import hashlib
from datetime import datetime

# ---------------- DATABASE CONNECTION ---------------- #

conn = sqlite3.connect("smartpay.db", check_same_thread=False)
cursor = conn.cursor()

# ---------------- CREATE TABLES ---------------- #

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    name TEXT,
    mobile TEXT UNIQUE,
    password TEXT,
    pin TEXT,
    balance REAL DEFAULT 0
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_mobile TEXT,
    receiver_mobile TEXT,
    amount REAL,
    timestamp TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_mobile TEXT,
    friend_mobile TEXT,
    added_on TEXT
)
""")

conn.commit()

# ---------------- SESSION & LOGIN PERSISTENCE ---------------- #

query_params = sst.query_params


if "user" in query_params and "user" not in st.session_state:
    st.session_state.user = query_params["user"][0]

if "user" not in st.session_state:
    st.session_state.user = None

if "page" not in st.session_state:
    st.session_state.page = "Login"

# ---------------- HELPER FUNCTIONS ---------------- #

def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def register_user(username, name, mobile, password, pin):
    try:
        cursor.execute(
            "INSERT INTO users (username, name, mobile, password, pin, balance) VALUES (?, ?, ?, ?, ?, ?)",
            (username, name, mobile, hash_text(password), hash_text(pin), 1000)
        )
        conn.commit()
        return True
    except:
        return False

def login_user(mobile, password):
    cursor.execute(
        "SELECT * FROM users WHERE mobile=? AND password=?",
        (mobile, hash_text(password))
    )
    return cursor.fetchone()

def get_balance(mobile):
    cursor.execute("SELECT balance FROM users WHERE mobile=?", (mobile,))
    return cursor.fetchone()[0]

def get_username(mobile):
    cursor.execute("SELECT username FROM users WHERE mobile=?", (mobile,))
    return cursor.fetchone()[0]

def add_money(mobile, amount):
    cursor.execute(
        "UPDATE users SET balance = balance + ? WHERE mobile=?",
        (amount, mobile)
    )
    conn.commit()

def send_money(sender, receiver, amount, pin):
    try:
        conn.execute("BEGIN TRANSACTION")

        cursor.execute("SELECT balance, pin FROM users WHERE mobile=?", (sender,))
        sender_data = cursor.fetchone()

        if not sender_data:
            return "Sender not found"

        if sender_data[1] != hash_text(pin):
            return "Incorrect PIN"

        if sender_data[0] < amount:
            return "Insufficient Balance"

        cursor.execute("SELECT balance FROM users WHERE mobile=?", (receiver,))
        receiver_data = cursor.fetchone()

        if not receiver_data:
            return "Receiver not registered"

        cursor.execute("UPDATE users SET balance = balance - ? WHERE mobile=?",
                       (amount, sender))

        cursor.execute("UPDATE users SET balance = balance + ? WHERE mobile=?",
                       (amount, receiver))

        cursor.execute(
            "INSERT INTO transactions (sender_mobile, receiver_mobile, amount, timestamp) VALUES (?, ?, ?, ?)",
            (sender, receiver, amount, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

        conn.commit()
        return "Success"

    except:
        conn.rollback()
        return "Transaction Failed"

def add_friend(user, friend):
    cursor.execute("""
        SELECT * FROM friends 
        WHERE user_mobile=? AND friend_mobile=?
    """, (user, friend))

    if cursor.fetchone():
        return "Already Added"

    cursor.execute("""
        INSERT INTO friends (user_mobile, friend_mobile, added_on)
        VALUES (?, ?, ?)
    """, (user, friend, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    return "Friend Added"

# ---------------- STREAMLIT UI ---------------- #

st.title("💳 SmartPay - Closed Wallet")

menu = ["Login", "Register"]

choice = st.sidebar.selectbox(
    "Menu",
    menu,
    index=menu.index(st.session_state.page)
)

st.session_state.page = choice

# ---------------- REGISTER ---------------- #

if choice == "Register":
    st.subheader("Create Account")

    username = st.text_input("Choose Username")
    name = st.text_input("Full Name")
    mobile = st.text_input("Mobile Number")
    password = st.text_input("Password", type="password")
    pin = st.text_input("4-digit PIN", type="password")

    if st.button("Register"):
        if len(mobile) == 10 and len(pin) == 4:
            if register_user(username, name, mobile, password, pin):
                st.success("Account Created! ₹1000 added as welcome balance")
                st.session_state.page = "Login"
                st.experimental_rerun()
            else:
                st.error("Username or Mobile already exists")
        else:
            st.error("Invalid Mobile or PIN format")

# ---------------- LOGIN ---------------- #

elif choice == "Login":
    st.subheader("Login")

    mobile = st.text_input("Mobile")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = login_user(mobile, password)
        if user:
            st.session_state.user = mobile
            st.experimental_set_query_params(user=mobile)
            st.success("Logged In Successfully")
        else:
            st.error("Invalid Credentials")

    st.markdown("---")
    st.write("Don't have an account?")

    if st.button("Go to Register"):
        st.session_state.page = "Register"
        st.experimental_rerun()

# ---------------- DASHBOARD ---------------- #

if st.session_state.user:

    username = get_username(st.session_state.user)
    st.sidebar.success(f"Welcome {username}")
    
    option = st.sidebar.selectbox(
        "Select Option",
        ["Dashboard", "Add Money", "Send Money", "Friends", "Transactions", "Logout"]
    )

    if option == "Dashboard":
        balance = get_balance(st.session_state.user)
        st.subheader("Wallet Balance")
        st.success(f"₹ {balance}")

    elif option == "Add Money":
        st.subheader("Add Money")

        amount = st.number_input("Enter Amount", min_value=1.0)

        if st.button("Add"):
            add_money(st.session_state.user, amount)
            st.success("Money Added Successfully")

    elif option == "Send Money":
        st.subheader("Send Money")

        receiver = st.text_input("Receiver Mobile Number")
        amount = st.number_input("Amount", min_value=1.0)
        pin = st.text_input("Enter PIN", type="password")

        if st.button("Transfer"):
            result = send_money(st.session_state.user, receiver, amount, pin)
            if result == "Success":
                st.success("Transaction Successful")
            else:
                st.error(result)

    elif option == "Friends":
        st.subheader("Your Friends")

        cursor.execute("SELECT friend_mobile FROM friends WHERE user_mobile=?",
                       (st.session_state.user,))
        friends = cursor.fetchall()

        for f in friends:
            st.write(f"📱 {f[0]}")

    elif option == "Transactions":
        st.subheader("Transaction History")

        cursor.execute("""
            SELECT sender_mobile, receiver_mobile, amount, timestamp 
            FROM transactions
            WHERE sender_mobile=? OR receiver_mobile=?
            ORDER BY id DESC
        """, (st.session_state.user, st.session_state.user))

        data = cursor.fetchall()

        for row in data:
            st.write(f"{row[3]} | ₹{row[2]} | {row[0]} ➜ {row[1]}")

    elif option == "Logout":
        st.session_state.user = None
        st.experimental_set_query_params()
        st.success("Logged Out")
        st.session_state.page = "Login"
        st.experimental_rerun()
