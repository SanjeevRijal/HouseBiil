from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, RadioField, SelectMultipleField, widgets, FloatField
from wtforms.validators import DataRequired, Email

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class Password_Reset(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Change")

class Conform_Password(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])
    conform_password = PasswordField(" ConformPassword", validators=[DataRequired()])
    submit = SubmitField("Submit")


class BillForm(FlaskForm):
    amount = FloatField("Spend Amount", validators=[DataRequired()])
    spend_catagorey = StringField("Spend Catagory", validators=[DataRequired()])
    split_with = MultiCheckboxField("With who", validators=[DataRequired()], render_kw={"class": "custom-class"},
                                    choices=[], validate_choice=False)
    bill_submit = RadioField("Bill Send To Group:", choices=[("yes", "Yes"), ("no", "No")], validators=[DataRequired()])
    submit = SubmitField("Submit Bill")