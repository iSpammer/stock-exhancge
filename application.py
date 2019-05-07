import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Show account info"""
    acc = db.execute("SELECT * FROM 'users' WHERE id=:id", id = session["user_id"])
    if request.method == "POST":
        print("hi")
        passw = request.form.get("password")
        confPw = request.form.get("confPw")

        # User entered password
        if not request.form.get("password") or not request.form.get("confPw"):
            return apology("must provide password")

        # Confirm password matches
        elif passw != confPw:
            return apology("password dosnt match the entered one")

        # Hash the password
        hashPw = generate_password_hash(passw)
        rows = db.execute("UPDATE 'users' SET hash =:hash WHERE id=:id",hash = hashPw , id = session["user_id"])
        return apology("Password changed successfully", 200)

    else:
        print(acc)
        return render_template("account.html", name = acc[0]['username'], cash = acc[0]['cash'], id = acc[0]['id'])


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    cash = db.execute("SELECT cash FROM 'users' WHERE id=:id", id = session["user_id"])
    print(cash)
    print(cash[0]['cash'])
    """Buy shares of stock"""
    if request.method == "POST":
        share = lookup(request.form.get("sym"))
        if not share:
            return apology("Symbol dosnt exist")
        cashValue = int(cash[0]['cash']) - int(share['price'])
        if cashValue < 0:
            return apology("No enought money")
        print(cashValue)
        rows = db.execute("UPDATE 'users' SET cash =:cash WHERE id=:id",cash = cashValue , id = session["user_id"])
        return apology("done", 200)
    else:
        return render_template("buy.html", cash = cash[0]['cash'])


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    return jsonify("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username").lower())

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    # Submitting form
    if request.method == "POST":
        if not request.form.get("sym"):
            return apology("Please enter the stock's sybmbol")
        sym = request.form.get("sym")
        share = lookup(sym)
        if not share:
            return apology("Stock dosnt exist!")
        return render_template("quoted.html",name = share['name'] , symbol = share['symbol'] , share = share['price'] )

    # Clicking the link
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST
    if request.method == "POST":
        passw = request.form.get("password")
        confPw = request.form.get("confPw")
        # User entered username
        if not request.form.get("username"):
            return apology("must provide username")

        # User entered password
        elif not request.form.get("password") or not request.form.get("confPw"):
            return apology("must provide password")

        # Confirm password matches
        elif passw != confPw:
            return apology("password dosnt match the entered one")

        # Hash the password
        hashPw = generate_password_hash(passw)
        user=request.form.get("username")
        # Insert user into database
        result = db.execute("INSERT INTO users (username, hash) VALUES (:user, :hashPw)",
                            user=user.lower(), hashPw=hashPw)
        print(result)
        if not result:
            return apology("username already registred")
        else:
            return apology("registration complete", 200)

        #Remember user
        session["user_id"] = result

        return redirect("/")

    #User reached route via GET
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
