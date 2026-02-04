from flask import Flask, request, render_template_string, sqlite3, make_response, redirect
import pickle
import base64
import os

app = Flask(__name__)
app.secret_key = "super_hemlig_nyckel_som_inte_ska_vara_i_koden" # Behövs för sessioner

# --- DATABAS SETUP ---
def get_db():
    # Vi använder check_same_thread=False för enkelhetens skull i denna demo
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    conn.row_factory = sqlite3.Row # Så vi kan nå kolumner med namn
    return conn

# Initiera DB och skapa tabell
db = get_db()
cursor = db.cursor()
# Notera: password_hash kolumnen är ny för A02
cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT NOT NULL, 
        secret TEXT,
        password_hash TEXT
    )
''')
# Lägg till startdata
cursor.execute("INSERT INTO users (username, secret, password_hash) VALUES (?, ?, ?)", (1, 'admin', 'Superhemligt_Lösenord_2026', 'YWRtaW4xMjM=')) # 'admin123' i base64
cursor.execute("INSERT INTO users (username, secret, password_hash) VALUES (?, ?, ?)", (2, 'kalle', 'min_hund_heter_todd', 'a2FsbGU=')) # 'kalle' i base64
db.commit()


# ==========================================
# SÅRBARHETSLABBEN
# ==========================================

@app.route('/')
def index():
    return """
    <h1>OWASP Top 10 (2025) Lab</h1>
    <ul>
        <li><a href="/user?id=1">A05: Injection (SQLi)</a> - Testa lägg till ' OR 1=1' i URL:en</li>
        <li><a href="/profile/2">A01: Broken Access Control (IDOR)</a> - Testa byt ID till 1</li>
        <li><a href="/reset-password">A04: Insecure Design</a> - Gissa svaret för användaren 'admin'</li>
        <li><a href="/dashboard">A08: Integrity Failures (Insecure Deserialization)</a> - Använd exploit.py</li>
        <li><a href="/register">A02: Cryptographic Failures</a> - Registrera en användare och se hur lösenordet sparas</li>
        <li><a href="/debug-error">A10: Exceptional Conditions</a> - Trigga ett fel</li>
    </ul>
    """

# --- SÅRBARHET 1: A05:2025 - Injection (SQLi) ---
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # SÅRBART: F-string direkt i SQL
    try:
        query = f"SELECT username, secret FROM users WHERE id = {user_id}"
        db_cursor = db.execute(query)
        result = db_cursor.fetchone()
        if result:
            return f"Användare: {result['username']}, Hemlighet: {result['secret']}"
        return "Användare hittades inte."
    except Exception as e:
        return f"SQL Error: {e}"

# --- SÅRBARHET 2: A01:2025 - Broken Access Control (IDOR) ---
@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    # SÅRBART: Ingen kontroll av vem som är inloggad vs vem som efterfrågas.
    db_cursor = db.execute("SELECT username, secret FROM users WHERE id = ?", (user_id,))
    user = db_cursor.fetchone()
    if user:
         return f"<h1>Profil för {user['username']}</h1><p>Hemlig data: {user['secret']}</p>"
    return "Hittades inte.", 404

# --- SÅRBARHET 3: A04:2025 - Insecure Design ---
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    # SÅRBART: Svag affärslogik. En gissningsbar fråga som enda skydd.
    if request.method == 'POST':
        user = request.form.get('username')
        answer = request.form.get('color')
        
        if user == 'admin' and answer and answer.lower() == 'blå':
            return f"<h2 style='color:red'>SUCCESS!</h2> Lösenordet för {user} har återställts."
        return "Fel svar eller användare.", 403
    
    return '''
        <form method="post">
            <h3>Återställ lösenord</h3>
            Användarnamn (testa 'admin'): <input name="username"><br>
            Säkerhetsfråga: Vad är din favoritfärg? <input name="color"><br>
            <input type="submit" value="Återställ">
        </form>
    '''

# --- SÅRBARHET 4: A08:2025 - Software and Data Integrity Failures ---
@app.route('/dashboard')
def dashboard():
    auth_cookie = request.cookies.get('user_session')
    
    if not auth_cookie:
        # Skapa en "oskyldig" cookie
        user_data = {'username': 'gäst', 'role': 'user'}
        # Vi använder pickle, vilket är roten till det onda här
        pickled_data = base64.b64encode(pickle.dumps(user_data)).decode()
        resp = make_response("Välkommen! En session-cookie har satts. Ladda om sidan.")
        resp.set_cookie('user_session', pickled_data)
        return resp

    try:
        # SÅRBART: pickle.loads() på okänd data från användaren = RCE
        decoded_data = pickle.loads(base64.b64decode(auth_cookie))
        # Om exploiten körs, kommer koden ovan att exekvera kommandot,
        # och ofta krascha här nere för att returvärdet inte är en dict.
        return f"Välkommen tillbaka, {decoded_data.get('username')}! Roll: {decoded_data.get('role')}"
    except Exception as e:
        # Om exploiten lyckas ser du ofta inget här i webbläsaren, titta i server-terminalen!
        return f"Något gick fel vid deserialisering (Kolla terminalen om du körde exploiten!): {e}"

# --- NY SÅRBARHET 5: A02:2025 - Cryptographic Failures ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return "Fyll i alla fält."

        # SÅRBART: Vi använder Base64 för att "skydda" lösenordet. 
        # Detta är INTE kryptering, det är bara kodning och trivialt att återställa.
        # KORREKT SÄTT: Använd bcrypt eller argon2 (t.ex. via passlib eller flask-bcrypt).
        pseudo_encrypted_password = base64.b64encode(password.encode()).decode()
        
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                       (username, pseudo_encrypted_password))
            db.commit()
            return redirect('/dump-users')
        except Exception as e:
             return f"Kunde inte registrera: {e}"

    return '''
        <h3>Registrera ny användare (A02 Demo)</h3>
        <form method="post">
            Username: <input name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Registrera">
        </form>
    '''

# Hjälp-route för att demonstrera A02 (visar databasens innehåll)
@app.route('/dump-users')
def dump_users():
    db_cursor = db.execute("SELECT username, password_hash FROM users")
    users = db_cursor.fetchall()
    
    html = "<h3>Databasdump (Visar Cryptographic Failure)</h3>"
    html += "<p>Notera att 'password_hash' bara är base64-kodat. En angripare som läcker databasen (via SQLi) får alla lösenord i klartext.</p>"
    html += "<table border='1'><tr><th>Username</th><th>Stored 'Hash' (Base64)</th></tr>"
    for user in users:
        # Vi visar Base64-strängen
        html += f"<tr><td>{user['username']}</td><td>{user['password_hash']}</td></tr>"
    html += "</table>"
    html += "<br><a href='/register'>Tillbaka till registrering</a>"
    return html


# --- SÅRBARHET 6: A10:2025 - Mishandling of Exceptional Conditions ---
@app.route('/debug-error')
def cause_error():
    # SÅRBART: Exponerar stack trace i produktion.
    # KORREKT SÄTT: Fånga felet, logga det internt, visa en generisk "500 Oups"-sida.
    return 1 / 0

if __name__ == '__main__':
    # Lyssna på alla interfaces så du kan testa från en annan maskin om du vill
    app.run(debug=True, host='0.0.0.0', port=5000)