import numpy as np
import pandas as pd
from flask import Flask, request, render_template, make_response, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pickle
import matplotlib.pyplot as plt
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
import re


app = Flask(__name__)
app.config['SECRET_KEY'] = '1234khaoula456aya789'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

model = pickle.load(open('BreastCancerDetectionWebsite/model.pkl', 'rb'))

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)


with app.app_context():
    db.create_all()
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/about')
def about():
    return render_template('AboutUs.html')

@app.route('/contact')
def contact():
    return render_template('contactUs.html')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/view')
def view():
    return render_template('view.html',values=User.query.all())

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password1 = request.form['password1']
    password2 = request.form['password2']
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        flash('Invalid email format!', category='error')
        return redirect(url_for('login'))
    
    if password1 != password2:
        print("password1 != password2")
        flash('Passwords do not match!', category='error')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username).first()
    if user:
        flash('Username already exists.', category='error')
    else:
        new_user = User(email=email, username=username, password=generate_password_hash(password1, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()
        flash('Registered successfully!', category='success')
        return redirect(url_for('login'))
    
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return render_template('index.html')
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Username does not exist.', category='error')

    return render_template("Login.html", user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', category='success')
    return redirect(url_for('login'))

@app.route('/edit_profile',methods=['GET', 'POST'])
@login_required  
def edit_profile():
    if request.method == 'POST':
        user = current_user  
        old_password = request.form.get('old_password')
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_password1 = request.form.get('password1')
        new_password2 = request.form.get('password2')

        if not any([old_password, new_username, new_email, new_password1, new_password2]):
            flash('Please fill at least one field to update!', category='error')
            return redirect(url_for('edit_profile'))
        
        if not old_password:
            flash('Old password is empty!', category='error')
        else :
            if not check_password_hash(user.password, old_password):
                flash('Old password is incorrect!', category='error')
                return redirect(url_for('edit_profile'))

        if new_password1 != new_password2:
            flash('Passwords do not match!', category='error')
            return redirect(url_for('edit_profile'))

        
        if new_username:
            user.username = new_username
        if new_email:
            user.email = new_email
        if new_password1:
            user.password = generate_password_hash(new_password1, method='pbkdf2:sha256')


        db.session.commit()

        flash('Profile updated successfully!', category='success')
        return redirect(url_for('profile'))
    else:
        return render_template('profile.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')


@app.route('/predict', methods=['POST'])
def predict():
    input_features = [int(x) for x in request.form.values()]
    features_value = [np.array(input_features)]

    features_name = ['clump_thickness', 'uniform_cell_size', 'uniform_cell_shape',
                     'marginal_adhesion', 'single_epithelial_size', 'bare_nuclei',
                     'bland_chromatin', 'normal_nucleoli', 'mitoses']

    df = pd.DataFrame(features_value, columns=features_name)
    output = model.predict(df)

    prediction = output[0]

    if prediction == 4:
        res_val = "Breast cancer"
    else:
        res_val = "No breast cancer"

    chart_data = input_features
    breast_cancer_count = output.tolist().count(4)
    no_breast_cancer_count = len(output) - breast_cancer_count

    prediction_text = f'Patient has {res_val}'

    return render_template('index.html', prediction_text=prediction_text,
                           chart_data=chart_data, breast_cancer_count=breast_cancer_count,
                           no_breast_cancer_count=no_breast_cancer_count)

def create_pdf(prediction_text, chart_data):
    pdf_bytes = BytesIO()
    plt.figure(figsize=(8, 12))

    plt.subplot(2, 1, 1)
    plt.bar(range(len(chart_data)), chart_data)
    plt.xlabel('Feature Index')
    plt.ylabel('Feature Value')
    plt.title('Input Features', fontsize=12, weight='bold', color='Blue')

    plt.subplot(2, 1, 2)
    plt.pie(chart_data, labels=[f'Feature {i+1}' for i in range(len(chart_data))], autopct='%1.1f%%')
    plt.title('Input Features Distribution', fontsize=12, weight='bold', color='Blue')
    plt.figtext(0.5, 0.98, 'TEST RESULT', fontsize=12, ha='center', weight='bold', color='Green')
    plt.figtext(0.5, 0.95, prediction_text, fontsize=12, ha='center')

    plt.subplots_adjust(top=0.9)
    plt.savefig(pdf_bytes, format='pdf')

    file_path = 'prediction_result.pdf'
    with open(file_path, 'wb') as f:
        f.write(pdf_bytes.getvalue())

    return file_path

@app.route('/generate_pdf_or_print')
def generate_pdf():
    prediction_text = request.args.get('prediction_text')
    chart_data = [int(x) for x in request.args.getlist('chart_data')]
    pdf_file = create_pdf(prediction_text, chart_data)
    response = make_response(send_file(pdf_file, as_attachment=True))
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response

if __name__ == "__main__":
    app.run()
