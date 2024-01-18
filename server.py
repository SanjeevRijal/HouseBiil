from flask import Flask, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, RadioField, SelectMultipleField, widgets, FloatField
from wtforms.validators import DataRequired, Email
from datetime import date, timedelta
from keys import flask_keys,sql_key
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("flask_key")
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI","sqlite:///Spending.db")
db = SQLAlchemy()
db.init_app(app)


# creating multiple checkbox field
class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    who_spend = relationship("Bill", back_populates="what_amount")
    pay_share = relationship("Split", back_populates="split_among")


class Bill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    spend_type = db.Column(db.String(250), nullable=False)
    spend_date = db.Column(db.Date, nullable=False)
    spender_id = db.Column(db.Integer, db.ForeignKey(User.id))
    what_amount = relationship("User", back_populates="who_spend")
    who_pay = relationship("Split", back_populates="bill_detail")


class Split(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    split_with = db.Column(db.Integer, db.ForeignKey(User.id))
    bill_id = db.Column(db.Integer, db.ForeignKey(Bill.id))
    split_among = relationship("User", back_populates="pay_share")
    bill_detail = relationship("Bill", back_populates="who_pay")


with app.app_context():
    db.create_all()


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class BillForm(FlaskForm):
    amount = FloatField("Spend Amount", validators=[DataRequired()])
    spend_catagorey = StringField("Spend Catagory", validators=[DataRequired()])
    split_with = MultiCheckboxField("With who", validators=[DataRequired()], render_kw={"class": "custom-class"})
    bill_submit = RadioField("Bill Send To Group:", choices=[("yes", "Yes"), ("no", "No")], validators=[DataRequired()])
    submit = SubmitField("Submit Bill")


@app.route("/add_bill", methods=["GET", "POST"])
@login_required
def add_bills():
    bill_form = BillForm()
    results = db.session.execute(db.select(User).where(User.id != current_user.get_id())).scalars().all()

    bill_form.split_with.choices = [(query.name, query.name) for query in results]
    if bill_form.validate_on_submit():
        new_bill = Bill(
            amount=bill_form.amount.data,
            spend_type=bill_form.spend_catagorey.data,
            spend_date=date.today(),
            spender_id=current_user.get_id(),
        )
        db.session.add(new_bill)
        db.session.commit()

    # gathering last bill of this user to insert data on Split table
        last_bill = db.session.execute(db.select(Bill.id)
                                       .where(Bill.spender_id == current_user.get_id())
                                       .order_by(Bill.id.desc())).first()
        last_bill_id = last_bill[0]
        for each_user in bill_form.split_with.data:
            split_with = Split(
                split_with=each_user,
                bill_id=last_bill_id, )
            db.session.add(split_with)
            db.session.commit()
        return redirect(url_for("home"))

    return render_template("add_bill.html", form=bill_form,
                           is_logged=current_user.is_authenticated)


@app.route("/home")
@login_required
def home():
    current_date = date.today()

    last_10_bills = db.session.execute(db.select(Bill)).scalars().all()

    # this block here is using function calculation to calculate receivable or payable

    bills_to_receive = db.session.execute(
        db.select(Bill).where(Bill.spender_id == current_user.get_id())).scalars().all()

    # this will calculate what the user will have to pay
    bills_to_pay = db.session.execute(
        db.select(Bill).where(Bill.spender_id != current_user.get_id())).scalars().all()


    # calculate what the user will have to pay
    to_pay = calculation(bills_to_pay, to_pay=True)

    # calculate what the user will receive
    to_receive = calculation(bills_to_receive)

    final_payment_dict = {}
    for individual_bill in to_receive:
        final_payment_dict[individual_bill] = []
        if individual_bill in to_pay:
            final_payment_dict[individual_bill].append(to_receive[individual_bill] - to_pay[individual_bill])
        else:
            final_payment_dict[individual_bill].append(to_receive[individual_bill])

    for individual_bill in to_pay:
        if individual_bill not in to_receive:
            final_payment_dict[individual_bill] = []
            final_payment_dict[individual_bill].append(-(to_pay[individual_bill]))

    balance = 0
    for final_payment in final_payment_dict:
        balance += final_payment_dict[final_payment][0]

    # calculating last month spending against this month
    one_month_ago = current_date - timedelta(days=30)
    last_month = db.session.execute(db.select(Bill.amount).where(Bill.spend_date < one_month_ago)).scalars().all()
    this_month = db.session.execute(db.select(Bill.amount).where(Bill.spend_date > one_month_ago)).scalars().all()
    last_month_result = sum(last_month)
    this_month_result = sum(this_month)
    if last_month_result < this_month_result:
        symbol = "static/assets/img/arrowup.png"
    elif last_month_result > this_month_result:
        symbol = "static/assets/img/arrowdown.png"
    else:
        symbol = None

    return render_template("logedinPage.html"
                           , last_10_bills=last_10_bills, result=this_month_result, balance=balance,
                           symbol=symbol, is_logged=current_user.is_authenticated,
                           final_payment_dict=final_payment_dict)


def calculation(pass_bills, to_pay=False):
    '''this function will calculate either user will need to pay or revive.
    It expects a parameter as scalars object in list form '''

    # creating set for this user with whom current_user is either paying or receiving
    to_receive_set = set()
    to_give_set = set()

    # empty dict to store final calculation value
    all_bill_in_dict = {}

    # storing values to above sets
    for bill_id in pass_bills:
        share_among = db.session.execute(db.select(Split.split_with).where(Split.bill_id == bill_id.id)).scalars().all()
        if not to_pay:
            for each_split_with in share_among:
                to_receive_set.add(each_split_with)
        else:
            to_give_set.add(bill_id.what_amount.name)

        # creating dictionary of individual bill
        bill_dict = {
            "amount": bill_id.amount,
            "with_whom": share_among,
            "how_many_to split": len(share_among),
            "spender_id": bill_id.what_amount.name, }

        # updating individual bill to this dictionary
        all_bill_in_dict[f'bill_id:{bill_id.id}'] = bill_dict

    final_dict_with_amount_to_receive = {}
    final_dict_with_amount_to_give = {}
    # creating empty dictionary of all user that needs to make or receive payment
    if not to_pay:
        for _ in to_receive_set:
            final_dict_with_amount_to_receive[_] = []
    else:
        for _ in to_give_set:
            final_dict_with_amount_to_give[_] = []

    # calculating final bills and returning values
    for individual_bill in all_bill_in_dict:
        values_to_calculate = all_bill_in_dict[individual_bill]
        each_person_share = values_to_calculate["amount"] / (values_to_calculate["how_many_to split"] + 1)

        if not to_pay:
            for _ in values_to_calculate["with_whom"]:

                final_dict_with_amount_to_receive[_].append(each_person_share)

        else:
            final_dict_with_amount_to_give[values_to_calculate["spender_id"]].append(each_person_share)

    if not to_pay:
        total = {key: sum(value) for key, value in final_dict_with_amount_to_receive.items()}

    else:
        total = {key: sum(value) for key, value in final_dict_with_amount_to_give.items()}

    return total


@app.route('/', methods=[ "GET", "POST"])
def login():
    loginform = LoginForm()
    if loginform.validate_on_submit():
        query = db.session.execute(db.select(User).where(User.email == loginform.email.data))
        query = query.scalar()
        if query:
            if check_password_hash(query.password, loginform.password.data):
                login_user(query)
                return redirect(url_for("home"))
            else:
                flash("Password not correct")
                return redirect(url_for("login"))
        else:
            flash("User not register. Register First")
            return redirect(url_for("login"))

    return render_template("login.html", loginform=loginform, is_logged=current_user.is_authenticated)



@app.route("/register", methods=["POST", "GET"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        query = db.session.execute(db.select(User).where(User.email == register_form.email.data)).scalar()
        if query:
            flash("User already Register. Try with new email")
            return redirect(url_for('register'))
        else:
            new_user = User(
                email=register_form.email.data,
                password=generate_password_hash(register_form.password.data, method='pbkdf2', salt_length=16),
                name=register_form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("login"))

    return render_template("register.html", registerForm=register_form, is_logged=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True, port=5004)
