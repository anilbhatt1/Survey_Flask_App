from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

#Create a flask instance

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'

# Create a Form class
class NamerForm(FlaskForm):
    name = StringField("What's your name?", validators = [DataRequired()])
    submit = SubmitField("Submit")

#Create route decorator
@app.route('/')

def index():
    message = ' <strong> Please go to Names tab to register your profile </strong>'
    return render_template("index.html",
                           message = message
                           )
# localhost:5000/user/Anil
@app.route('/user/<name>')
def user(name):
#   return "<h1>Hello {} !!! </h1>" .format(name)
    return render_template('user.html', user_name=name)

#Create custom error pages

#Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

#Internal server error
@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500

#Create Name Page
@app.route('/name',methods=['GET', 'POST'])
def name():
    name = None
    form = NamerForm()
    # Validate Form
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''

    return render_template('name.html',
                           name=name,
                           form=form)