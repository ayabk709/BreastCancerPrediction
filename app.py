import numpy as np
import pandas as pd
from flask_mail import Mail, Message
from flask import Flask, request, render_template, make_response, send_file,send_file, redirect, url_for, flash
import pickle
import matplotlib.pyplot as plt
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_mail import Message
from flask import current_app
from datetime import datetime

app = Flask(__name__)

 


#######################

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'aya.bekkach@gmail.com'
app.config['MAIL_PASSWORD'] = 'uhykhgqctydswelv'

mail = Mail(app)
def send_email_notification(subject, recipient, body):
    msg = Message(subject, sender=current_app.config['MAIL_USERNAME'], recipients=[recipient])
    msg.body = body
    mail.send(msg)

@app.route('/predict', methods=['POST'])
def predict():
    input_features = [int(x) for x in request.form.values()]
    features_value = [np.array(input_features)]

    features_name = ['clump_thickness', 'uniform_cell_size', 'uniform_cell_shape',
                     'marginal_adhesion', 'single_epithelial_size', 'bare_nuclei',
                     'bland_chromatin', 'normal_nucleoli', 'mitoses']

    df = pd.DataFrame(features_value, columns=features_name)
    output = model.predict(df)

    # Extracting the first element of the output array
    prediction = output[0]

    if prediction == 4:
        res_val = "Breast cancer"
    else:
        res_val = "No breast cancer"

    new_prediction = Prediction(
        clump_thickness=input_features[0],
        uniform_cell_size=input_features[1],
        uniform_cell_shape=input_features[2],
        marginal_adhesion=input_features[3],
        single_epithelial_size=input_features[4],
        bare_nuclei=input_features[5],
        bland_chromatin=input_features[6],
        normal_nucleoli=input_features[7],
        mitoses=input_features[8],
        result=res_val,
        user_id=current_user.id
    )
    db.session.add(new_prediction)
    db.session.commit()
    ##
    chart_data = input_features
    breast_cancer_count = output.tolist().count(4)
    no_breast_cancer_count = len(output) - breast_cancer_count

    prediction_text = 'Patient has {}'.format(res_val)  # Create prediction text here

    # Sending email notification to the user
    subject = "Breast Cancer Prediction"
    recipient = 'aya.bekkach@gmail.com'  # Change this to the actual recipient's email address
    body = f"Prediction: {res_val}"
    send_email_notification(subject, recipient, body)

    # Render the template including the prediction text and chart data
    return render_template('index.html', prediction_text=prediction_text,
                           chart_data=chart_data, breast_cancer_count=breast_cancer_count,
                           no_breast_cancer_count=no_breast_cancer_count)

#######################


app.config['SECRET_KEY'] = '1234khaoula456aya789'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///predictions.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

model = pickle.load(open('model.pkl', 'rb'))
#############
class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clump_thickness = db.Column(db.Integer)
    uniform_cell_size = db.Column(db.Integer)
    uniform_cell_shape = db.Column(db.Integer)
    marginal_adhesion = db.Column(db.Integer)
    single_epithelial_size = db.Column(db.Integer)
    bare_nuclei = db.Column(db.Integer)
    bland_chromatin = db.Column(db.Integer)
    normal_nucleoli = db.Column(db.Integer)
    mitoses = db.Column(db.Integer)
    result = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

#######
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
# 
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
@app.route('/profile')
def profile():
    return render_template('profile.html')
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', category='success')
    return redirect(url_for('login'))
# 
@app.route('/about')
def about():
    return render_template('AboutUs.html')

@app.route('/history')
@login_required
def history():
    predictions = db.session.query(Prediction.timestamp, Prediction.clump_thickness, Prediction.uniform_cell_size, Prediction.uniform_cell_shape, Prediction.marginal_adhesion, Prediction.single_epithelial_size, Prediction.bare_nuclei, Prediction.bland_chromatin, Prediction.normal_nucleoli, Prediction.mitoses, Prediction.result).filter_by(user_id=current_user.id).order_by(Prediction.timestamp.desc()).all()
    return render_template('history.html', predictions=predictions)

@app.route('/contact')
def contact():
    return render_template('ContactUs.html')

@app.route('/')
def home():
    return render_template('index.html')

def create_pdf(prediction_text, chart_data):
    # Create a BytesIO object to store the PDF data
    pdf_bytes = BytesIO()

    # Create a new figure
    plt.figure(figsize=(8, 12))

    # Add the bar chart
    plt.subplot(2, 1, 1)  # 2 rows, 1 column, first subplot
    plt.bar(range(len(chart_data)), chart_data)
    plt.xlabel('Feature Index')
    plt.ylabel('Feature Value')
    plt.title('Input Features', fontsize=12, weight='bold', color='Blue')

    # Add the pie chart
    plt.subplot(2, 1, 2)  # 2 rows, 1 column, second subplot
    plt.pie(chart_data, labels=[f'Feature {i+1}' for i in range(len(chart_data))], autopct='%1.1f%%')
    plt.title('Input Features Distribution', fontsize=12, weight='bold', color='Blue')
    plt.figtext(0.5, 0.98, 'TEST RESULT', fontsize=12, ha='center', weight='bold', color='Green')

    # Add text with prediction result
    plt.figtext(0.5, 0.95, prediction_text, fontsize=12, ha='center')

    # Adjust layout to prevent overlap
    plt.subplots_adjust(top=0.9)  # Adjust the top margin to move the plots down

    # Save the plot to the BytesIO object
    plt.savefig(pdf_bytes, format='pdf')
    plt.close()  # Close the plot to free memory

    # Rewind the BytesIO object
    pdf_bytes.seek(0)

    return pdf_bytes


@app.route('/generate_pdf')
def generate_pdf():
    # Extract prediction text from the request parameters
    prediction_text = request.args.get('prediction_text')
    chart_data_str = request.args.get('chart_data')

    # Split the string into individual values and convert them to integers
    chart_data = [int(x) for x in chart_data_str.split(',')]

    # Generate the PDF file with the provided prediction text
    pdf_bytes = create_pdf(prediction_text, chart_data)

    # Create a response to download the PDF file
    response = make_response(send_file(pdf_bytes, as_attachment=True, download_name='report.pdf', mimetype='application/pdf'))
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'

    return response


if __name__ == "__main__":
    app.run()
