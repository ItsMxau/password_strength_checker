import re
import requests
import hashlib

from flask import Flask, render_template, request

app = Flask(__name__)

def check_password_strength1(password):
    # Check if password is at least 8 characters long
    if len(password) < 8:
        return False
    
    # Check if password contains at least one uppercase letter
    if not re.search("[A-Z]", password):
        return False
    
    # Check if password contains at least one lowercase letter
    if not re.search("[a-z]", password):
        return False
    
    # Check if password contains at least one digit
    if not re.search("[0-9]", password):
        return False    
    
    return True  # Return True if all checks pass



def check_password_strength2(password):
    """Evaluates password strength based on length, uppercase, lowercase, digits, and special characters."""
    strength_criteria = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "special_chars": bool(re.search(r"[!@#$%^&*()_+=-]", password))
    }

    strength_score = sum(strength_criteria.values()) # This counts the number of satisified conditions

    if strength_score == 5:
        return "Very Strong"
    elif strength_score == 4:
        return "Strong"
    elif strength_score == 3:
        return "Medium"
    elif strength_score == 2:
        return "Weak"
    else:
        return "Very Weak"

def check_pwned_api(password):
    """Checks if the password has been exposed in data breaches using the HaveIBeenPwned API."""
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    
    # Send only first 5 so adversaries can't reconstruct password
    prefix, suffix = sha1_password[:5], sha1_password[5:] # first 5 sent to API, remaining used for checking API response

    url = f"https://api.pwnedpasswords.com/range/{prefix}" # sending the first 5 to API
    response = requests.get(url)

    # server responds with status code, if it is not 200, it is not ok; unsuccessful (200: special status HTTP code for OK)
    if response.status_code != 200:
        return "Error: Cannot access HaveIBeenPwned API"
    
    # Check if the suffix exists in the response data - it would look like this 008F9CAB4083784CBD1874F76618D2A97:1000  
    hashes = (line.split(":") for line in response.text.splitlines())
    
    for h, count in hashes:
        if h == suffix:
            return int(count)  # Return just the number of times found
    
    return 0  # Return 0 if not found



@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.form['password']
        
        # Get basic strength check
        basic_check = check_password_strength1(password)
        
        # Get detailed strength rating
        strength_rating = check_password_strength2(password)
        
        # Check if password has been pwned
        pwned_count = check_pwned_api(password)
        
        if pwned_count > 0:
            pwned_result = f"⚠️ Your password has been exposed {pwned_count:,} times! DO NOT USE IT. ⚠️"
        else:
            pwned_result = "✅ Good news! This password hasn't been found in any known data breaches."
        
        return render_template('index.html', 
                             pwned_result=pwned_result,
                             strength_rating=strength_rating,
                             basic_check=basic_check)
    
    return render_template('index.html')




if __name__ == "__main__":
    print("Flask app is starting...")
    app.run(debug=True, host='0.0.0.0', port=8080)

