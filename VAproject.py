import os
import datetime
import webbrowser
import pyttsx3
import speech_recognition as sr
import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from flask import Flask, jsonify, request
from email.mime.text import MIMEText
import base64
import threading
from flask_cors import CORS
from multiprocessing import Process
import sqlite3
from flask import Flask, jsonify, request, session
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from multiprocessing import Process


# Initialize recognizer and text-to-speech engine
listener = sr.Recognizer()
engine = pyttsx3.init()

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)
CORS(app)

# Update scopes to include Gmail API
SCOPES = [
    'https://www.googleapis.com/auth/calendar',
    'https://mail.google.com/'
]

# Weather and News API configurations
WEATHER_API_KEY = 'e3bd72c21bc88acc01eec69e1e774410'
NEWS_API_KEY = '5c747c203a144aa5a84c468370c3bbbd'
CITY = 'London'
COUNTRY_CODE = 'GB'



# User registration route
@app.route('/api/register', methods=['POST'])
def register_user():
    print(request.json)
    data = request.json
    username = data.get('email')
    password = data.get('password')
    print("HHHHHHHHHH")
    print(username)
    print(password)
    if not username or not password:
        return jsonify({"error": "Usernamnne and password are required"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

# User login route
@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.json
    username = data.get('email')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.check_password_hash(user[2], password):
        session['user_id'] = user[0]
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

# Route to check if a user is logged in
@app.route('/api/check_session', methods=['GET'])
def check_session():
    if 'user_id' in session:
        return jsonify({"logged_in": True})
    return jsonify({"logged_in": False})

# User logout route
@app.route('/api/logout', methods=['POST'])
def logout_user():
    session.pop('user_id', None)
    return jsonify({"message": "Logout successful"}), 200



def talk(text):
    engine.say(text)
    engine.runAndWait()

def listen():
    try:
        with sr.Microphone() as source:
            listener.adjust_for_ambient_noise(source)
            print("Listening...")
            voice = listener.listen(source)
            command = listener.recognize_google(voice)
            print(f"You said: {command}")
            return command.lower()
    except sr.UnknownValueError:
        talk("Sorry, I could not understand the audio.")
        return ""
    except sr.RequestError as e:
        talk(f"Could not request results; {e}")
        return ""
    except Exception as e:
        talk(f"An error occurred: {e}")
        return ""

def authenticate_google():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def authenticate_google_calendar():
    creds = authenticate_google()
    service = build('calendar', 'v3', credentials=creds)
    return service

def authenticate_google_gmail():
    creds = authenticate_google()
    service = build('gmail', 'v1', credentials=creds)
    return service

@app.route('/api/events', methods=['OPTIONS', 'GET'])
def get_events_for_today():
    service = authenticate_google_calendar()
    now = datetime.datetime.utcnow().isoformat() + 'Z'
    end_of_day = (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat() + 'Z'
    events_result = service.events().list(calendarId='primary', timeMin=now,
                                          timeMax=end_of_day, singleEvents=True,
                                          orderBy='startTime').execute()
    events = events_result.get('items', [])

    if not events:
        return jsonify({"events": "You have no events scheduled for today."})
    
    event_details = "Here are your events for today: "
    for event in events:
        start_time = event['start'].get('dateTime', event['start'].get('date'))
        start_time = datetime.datetime.fromisoformat(start_time).strftime('%I:%M %p')
        event_details += f"{event['summary']} at {start_time}. "
    
    return jsonify({"events": event_details})

@app.route('/api/weather', methods=['GET'])
def get_weather():
    url = f"http://api.openweathermap.org/data/2.5/weather?q={CITY}&appid={WEATHER_API_KEY}&units=metric"
    response = requests.get(url)
    data = response.json()
    
    if data["cod"] != 200:
        return jsonify({"weather": "I couldn't fetch the weather information."})
    
    weather_description = data['weather'][0]['description']
    temperature = data['main']['temp']
    weather_details = f"The weather in {CITY} is currently {weather_description} with a temperature of {temperature}°C."
    
    return jsonify({"weather": weather_details})

@app.route('/api/news', methods=['GET'])
def get_news():
    url = f"https://newsapi.org/v2/top-headlines?country={COUNTRY_CODE}&category=technology&apiKey={NEWS_API_KEY}"
    response = requests.get(url)
    articles = response.json().get('articles', [])
    
    if not articles:
        return jsonify({"news": "I couldn't fetch the latest news."})
    
    news_summary = "Here are the top news headlines: "
    for article in articles[:3]:  # Get the top 3 headlines
        news_summary += f"{article['title']}. "
    
    return jsonify({"news": news_summary})

@app.route('/api/emails', methods=['GET'])
def get_emails():
    try:
        service = authenticate_google_gmail()
        results = service.users().messages().list(userId='me', maxResults=5).execute()
        messages = results.get('messages', [])

        if not messages:
            return jsonify({"emails": []})

        emails = []
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            snippet = msg_data['snippet']
            payload = msg_data.get('payload', {}).get('headers', [])
            sender = next((header['value'] for header in payload if header['name'] == 'From'), 'Unknown sender')
            subject = next((header['value'] for header in payload if header['name'] == 'Subject'), 'No subject')
            
            emails.append({
                "sender": sender,
                "subject": subject,
                "snippet": snippet
            })

        return jsonify({"emails": emails})

    except Exception as e:
        print(f"Error fetching emails: {e}")
        return jsonify({"error": "Failed to fetch emails"}), 500



def create_email_message(to, subject, body):
    message = MIMEText(body)
    message['to'] = 'armubbu@gmail.com'
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes())
    return {'raw': raw.decode()}

def send_email(to, subject, body):
    try:
        service = authenticate_google_gmail()
        email_message = create_email_message(to, subject, body)
        send_message = service.users().messages().send(userId="me", body=email_message).execute()
        talk("Email sent successfully.")
    except Exception as e:
        talk(f"Failed to send email: {e}")

def handle_email_composition():
    talk("Please provide the recipient's email address.")
    recipient = listen()

    talk("What is the subject of the email?")
    subject = listen()

    talk("Please dictate the body of the email.")
    body = listen()

    send_email(recipient, subject, body)

def daily_briefing():
    with app.app_context():
        # Fetch schedule
        schedule = get_events_for_today().json['events']
        
        # Fetch weather
        weather = get_weather().json['weather']
        
        # Fetch news
        news = get_news().json['news']
        
        # Fetch emails
        emails = get_emails().json['emails']
        
        # Provide the daily briefing
        talk(f"Good morning! {schedule} {weather} {news} {emails}")

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    user_message = data.get('message')
    
    if not user_message:
        return jsonify({"response": "I didn't catch that. Please say it again."})

    # Process the user's message with the assistant
    response = process_command(user_message)
    
    return jsonify({"response": response})

def process_command(command):
    command = command.lower()

    if "time" in command:
        return f"Current time is {datetime.datetime.now().strftime('%I:%M %p')}"

    elif "date" in command:
        return f"Today's date is {datetime.datetime.now().strftime('%Y-%m-%d')}"

    elif "open google" in command:
        webbrowser.open("https://www.google.com")
        return "Opening Google"

    elif "play music" in command:
        music_dir = "path_to_music_directory"
        songs = os.listdir(music_dir)
        os.startfile(os.path.join(music_dir, songs[0]))
        return "Playing music"

    elif "good morning" in command or "what's my schedule for today" in command:
        return daily_briefing()

    elif "write email" in command:
        # Add your email handling code here
        handle_email_composition()

    else:
        return "I didn't catch that. Please say it again."


def run_assistant():
    while True:
        command = listen()

        if "time" in command:
            current_time = datetime.datetime.now().strftime('%I:%M %p')
            talk(f"Current time is {current_time}")

        elif "date" in command:
            current_date = datetime.datetime.now().strftime('%Y-%m-%d')
            talk(f"Today's date is {current_date}")

        elif "open google" in command:
            webbrowser.open("https://www.google.com")
            talk("Opening Google")

        elif "play music" in command:
            music_dir = "path_to_music_directory"
            songs = os.listdir(music_dir)
            os.startfile(os.path.join(music_dir, songs[0]))
            talk("Playing music")

        elif "stop" in command or "exit" in command:
            talk("Goodbye!")
            break

        elif "good morning" in command or "what's my schedule for today" in command:
            daily_briefing()

        elif "write mail" in command:
            handle_email_composition()

        else:
            talk("I didn't catch that. Please say it again.")

def run_flask():
    app.run(debug=True, use_reloader=False)

if __name__ == "__main__":
    talk("Hello! How can I assist you today?")
    
    flask_process = Process(target=run_flask)
    assistant_process = Process(target=run_assistant)
    
    flask_process.start()
    assistant_process.start()
    
    flask_process.join()
    assistant_process.join()
