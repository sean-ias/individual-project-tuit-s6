import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from credit_card_validator import is_valid_card, is_supported_card
from cryptography import caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt
import rsa
import base64
from Crypto.Cipher import AES
from helpers import apology, login_required, lookup, usd

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
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    stocks = db.execute("SELECT symbol, name, SUM(shares) as total_shares, price FROM transactions where user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    total = cash
    for stock in stocks:
        total += stock["total_shares"] * stock["price"]
    return render_template("index.html", stocks = stocks, cash = cash, total = total, usd = usd)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    user_id = session["user_id"]
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        n = request.form.get("shares")
        item = lookup(symbol)
        if not symbol:
            return apology("must provide a symbol")
        elif not item:
            return apology("symbol not found!")
        elif not n or not n.isdigit():
            return apology("must provide a positive integer")
        money = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        n = int(n)
        total_price = n * item["price"]
        if total_price > money:
            return apology("not enough cash to buy shares!")
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", money - total_price, user_id)
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)", user_id, item["name"], n, item["price"], "buy", symbol)
        return redirect('/')
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    stocks = db.execute("SELECT symbol, shares, price, type, time FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", stocks = stocks, usd = usd)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("invalid symbol")
        stock = lookup(symbol)
        if stock:
            return render_template("quoted.html", stock = stock, usd = usd)
        else:
            return apology("symbol not found!")
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # Ensure username was submitted
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if not username:
            return apology("must provide username")
        # Ensure password was submitted
        elif not password:
            return apology("must provide password")
        elif not confirmation:
            return apology("must type the password again")
        elif password != confirmation:
            return apology("wrong password retyped")
        # Ensure the username doesn't already exist
        elif len(rows) > 0:
            return apology("such username already exists")
        # Generate hash password
        hashed_password = generate_password_hash(password)
        # Insert into database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    stocks = db.execute("SELECT symbol FROM transactions where user_id = ? GROUP BY symbol", user_id)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("Must choose a symbol")
        num = db.execute("SELECT shares FROM transactions WHERE symbol = ? AND user_id = ? GROUP BY symbol", symbol, user_id)
        shares = int(shares)
        if shares > num[0]["shares"]:
            return apology("You don't have that many shares")
        item = lookup(symbol)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)", user_id, item["name"], -shares, item["price"], "sell", symbol)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + shares * item["price"], user_id)
        return redirect('/')
    else:
        return render_template("sell.html", stocks = stocks)
    
@app.route('/check', methods=['GET', 'POST'])
@login_required
def check():
    """Check credit card validity"""
    if request.method == 'POST':
        card_number = request.form['card_number']
        if is_supported_card(card_number) and is_valid_card(card_number):
            card_type = ''
            if card_number[0] == '3':
                card_type = "American Express"
            elif card_number[0] == '4':
                card_type = "VISA"
            elif card_number[0] == '5':
                card_type = "Mastercard"
            elif card_number[0] == '8':
                card_type = "Uzcard"
            else:
                card_type = "Humo"
            return render_template('result.html', result=f'The card number is valid. The card type is {card_type}.')
        else:
            return render_template('result.html', result='The card number is invalid or not supported.')
    else:
        return render_template('check.html')
    
@app.route("/encrypt", methods=['GET', 'POST'])
@login_required
def encrypt():
    """Encrypt a message"""
    if request.method == 'POST':
        # Get the form data
        message = request.form["message"]
        key = request.form["key"]
        method = request.form["method"]
        todo = request.form["todo"]

        if todo == "Encrypt":
            if method == "caesar":
                encrypted_message = caesar_encrypt(message, int(key))
            elif method == "vigenere":
                encrypted_message = vigenere_encrypt(message, key)
            return render_template("crypto_result.html", message=encrypted_message)
        
        else:
            if method == "caesar":
                decrypted_message = caesar_decrypt(message, int(key))
            elif method == "vigenere":
                decrypted_message = vigenere_decrypt(message, key)
            return render_template("crypto_result.html", message=decrypted_message)
        # Encrypt the message using the selected method

    else:
        return render_template('encrypt.html')

@app.route('/rsa', methods=['GET', 'POST'])
def rsatool():
    pub_key_str = ''
    priv_key_str = ''
    key_size = 1024
    encrypted_text_str = ''
    decrypted_text_str = ''
    plain_text = ''
    if request.method == 'POST':
        if request.form['action'] == 'rsakeygen':
            # Get the selected key size from the form
            key_size = int(request.form['key_size'])

            # Generate the RSA key pair
            (pubkey, privkey) = rsa.newkeys(key_size)

            # Convert the keys to strings and base64 encode them
            pub_key_str = base64.b64encode(pubkey.save_pkcs1()).decode()
            priv_key_str = base64.b64encode(privkey.save_pkcs1()).decode()

            # Render the main page with the generated keys
        
        elif request.form['action'] == 'encrypt':
            # Get the plain text and public key from the form
            plain_text = request.form['plain_text']
            pub_key_str = request.form['pub_key']

            # Decode the public key from base64 and load it into the rsa library
            pub_key = rsa.PublicKey.load_pkcs1(base64.b64decode(pub_key_str))

            # Encrypt the plain text using the public key
            encrypted_text = rsa.encrypt(plain_text.encode(), pub_key)

            # Base64 encode the encrypted text to make it printable
            encrypted_text_str = base64.b64encode(encrypted_text).decode()

        elif request.form['action'] == 'decrypt':
            # Get the encrypted text and private key from the form
            encrypted_text_str = request.form['encrypted_text']
            priv_key_str = request.form['priv_key']

            # Decode the private key from base64 and load it into the rsa library
            priv_key = rsa.PrivateKey.load_pkcs1(base64.b64decode(priv_key_str))

            # Base64 decode the encrypted text
            encrypted_text = base64.b64decode(encrypted_text_str)

            # Decrypt the encrypted text using the private key
            decrypted_text = rsa.decrypt(encrypted_text, priv_key)

            # Decode the decrypted text from bytes to string
            decrypted_text_str = decrypted_text.decode()

        return render_template('rsa.html', key_size=key_size, pub_key=pub_key_str, priv_key=priv_key_str, encrypted_text=encrypted_text_str, decrypted_text=decrypted_text_str, plain_text=plain_text)
    else:
        return render_template('rsa.html')

# AES page
@app.route('/aes', methods=['GET', 'POST'])
def aes():
    encrypted_text = ''
    decrypted_text = ''
    plain_text = ''
    cipher_mode = 'cbc'
    key_size = '128'
    secret_key = ''

    if request.method == 'POST':
        if request.form['action'] == 'encrypt':
            plain_text = request.form['plain_text']
            cipher_mode = request.form['cipher_mode']
            key_size = request.form['key_size']
            secret_key = request.form['secret_key'].encode('utf-8')
            cipher = AES.new(secret_key, AES.MODE_CBC if cipher_mode == 'cbc' else AES.MODE_ECB)
            padded_text = plain_text + ((16 - len(plain_text) % 16) * chr(16 - len(plain_text) % 16))
            encrypted_text = base64.b64encode(cipher.encrypt(padded_text.encode('utf-8'))).decode('utf-8')

        elif request.form['action'] == 'decrypt':
            encrypted_text = request.form['encrypted_text']
            cipher_mode = request.form['cipher_mode']
            key_size = request.form['key_size']
            secret_key = request.form['secret_key'].encode('utf-8')
            cipher = AES.new(secret_key, AES.MODE_CBC if cipher_mode == 'cbc' else AES.MODE_ECB)
            decrypted_padded_text = cipher.decrypt(base64.b64decode(encrypted_text.encode('utf-8')))
            decrypted_text = decrypted_padded_text[:-decrypted_padded_text[-1]].decode('latin-1')

    return render_template('aes.html', encrypted_text=encrypted_text, decrypted_text=decrypted_text,
                           plain_text=plain_text, cipher_mode=cipher_mode, key_size=key_size, secret_key=secret_key)
