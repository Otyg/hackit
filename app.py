from flask import Flask, request, render_template_string, sqlite3, make_response, redirect
import pickle
import base64
import os

app = Flask(__name__)
app.secret_key = "aAddAaaZZZkk119900ZZZa"

def get_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

db = get_db()
cursor = db.cursor()
cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT NOT NULL, 
        secret TEXT,
        password_hash TEXT
    )
''')
cursor.execute("INSERT INTO users (username, secret, password_hash) VALUES (?, ?, ?)", (1, 'admin', 'Superhemligt_Lösenord_2026', 'YWRtaW4xMjM='))
cursor.execute("INSERT INTO users (username, secret, password_hash) VALUES (?, ?, ?)", (2, 'kalle', 'min_hund_heter_todd', 'a2FsbGU='))
db.commit()

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

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    try:
        query = f"SELECT username, secret FROM users WHERE id = {user_id}"
        db_cursor = db.execute(query)
        result = db_cursor.fetchone()
        if result:
            return f"Användare: {result['username']}, Hemlighet: {result['secret']}"
        return "Användare hittades inte."
    except Exception as e:
        return f"SQL Error: {e}"

@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    db_cursor = db.execute("SELECT username, secret FROM users WHERE id = ?", (user_id,))
    user = db_cursor.fetchone()
    if user:
         return f"<h1>Profil för {user['username']}</h1><p>Hemlig data: {user['secret']}</p>"
    return "Hittades inte.", 404

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
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

@app.route('/dashboard')
def dashboard():
    auth_cookie = request.cookies.get('user_session')
    
    if not auth_cookie:
        user_data = {'username': 'gäst', 'role': 'user'}
        pickled_data = base64.b64encode(pickle.dumps(user_data)).decode()
        resp = make_response("Välkommen! En session-cookie har satts. Ladda om sidan.")
        resp.set_cookie('user_session', pickled_data)
        return resp

    try:
        decoded_data = pickle.loads(base64.b64decode(auth_cookie))
        return f"Välkommen tillbaka, {decoded_data.get('username')}! Roll: {decoded_data.get('role')}"
    except Exception as e:
        return f"Något gick fel vid deserialisering (Kolla terminalen om du körde exploiten!): {e}"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return "Fyll i alla fält."

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

@app.route('/dump-users')
def dump_users():
    db_cursor = db.execute("SELECT username, password_hash FROM users")
    users = db_cursor.fetchall()
    
    html = "<h3>Databasdump (Visar Cryptographic Failure)</h3>"
    html += "<p>Notera att 'password_hash' bara är base64-kodat. En angripare som läcker databasen (via SQLi) får alla lösenord i klartext.</p>"
    html += "<table border='1'><tr><th>Username</th><th>Stored 'Hash' (Base64)</th></tr>"
    for user in users:
        html += f"<tr><td>{user['username']}</td><td>{user['password_hash']}</td></tr>"
    html += "</table>"
    html += "<br><a href='/register'>Tillbaka till registrering</a>"
    return html


@app.route('/debug-error')
def cause_error():
    return 1 / 0

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)