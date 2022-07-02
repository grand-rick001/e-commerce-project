import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///e-commerce.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# HOMEPAGE


@app.route("/", methods=["GET", "POST"])
# @login_required
def index():
    """Show homepage"""
    if request.method == "GET":
        return render_template("index.html")

# ALL PRODUCTS PAGE


@app.route("/all", methods=["GET", "POST"])
@login_required
def all():
    """Show all products"""
    return render_template("all.html")

# HISTORY


@app.route("/shop", methods=["GET", "POST"])
@login_required
def shop():
    """Show history of transactions"""
    return render_template("shop.html")

# LOGIN


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

# LOG OUT


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


# REGISTER


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Register user"""
    if request.method == "POST":
        firstname = request.form.get("firstName")
        username = request.form.get("userName")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensuring the fields are not blank
        if not firstname:
            return apology("Missing firstname")

        if not username:
            return apology("Missing username")
        
        if not email:
            return apology("Missing email")

        # Ensuring there is a password
        if not password or not confirmation:
            return apology("Missing password")

        # If password and apology don't match return error
        if password != confirmation:
            return apology("Passwords do not match")

        # Ensure password is atleast 6 characters
        if len(password) < 6:
            return apology("Password Length must be at least 6 characters long")

        # If username is already taken, return error
        name_check = db.execute("SELECT username FROM users WHERE username = ?", username)

        if not name_check:
            # Encrypt the password
            wordpass = generate_password_hash(password)
            db.execute("INSERT INTO users (firstname, username, email, hash) VALUES(?, ?, ?, ?)", firstname, username, email, wordpass)

            # Query database for username
            rows = db.execute("SELECT * FROM users WHERE username = ?", username)

            # Remember which user has logged in
            session["user_id"] = rows[0]["id"]

            # Redirect user to home page
            return redirect("/")
        else:
            return apology("Username already taken, please try another one")
    else:
        return render_template("signup.html")


if __name__ == "__main__":
    app.run(debug=True)