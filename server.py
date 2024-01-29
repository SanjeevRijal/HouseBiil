from flask import Flask, render_template, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON
from sqlalchemy.orm import relationship
from flask_bootstrap import Bootstrap5
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, timedelta, datetime
import os
import secrets
from flask_mail import Mail, Message
from form import BillForm,Password_Reset,Conform_Password,RegisterForm,LoginForm

app = Flask(__name__)


app.config['SECRET_KEY'] = os.environ.get("flask_key")
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get("email")
app.config['MAIL_PASSWORD'] = os.environ.get("password")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

Bootstrap5(app)
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI","sqlite:///Spending.db")
db = SQLAlchemy()
db.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
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

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payment_dict = db.Column(db.JSON, nullable=False)
    calculation_date= db.Column(db.Date, nullable=False)


class Split(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    split_with = db.Column(db.Integer, db.ForeignKey(User.id))
    bill_id = db.Column(db.Integer, db.ForeignKey(Bill.id))
    split_among = relationship("User", back_populates="pay_share")
    bill_detail = relationship("Bill", back_populates="who_pay")


with app.app_context():
    db.create_all()


def select_user(current_user):
    if current_user.get_id():
        user_id = current_user.get_id()
    else:
        user_id = current_user.id
    return user_id

def payment(current_user):
    current_date = date.today()
    first_day_of_month = datetime(datetime.now().year, datetime.now().month, 1)

    # this block here is using function calculation to calculate receivable or payable

    bills_to_receive = Bill.query.filter(Bill.spender_id == select_user(current_user),
                                         Bill.spend_date >= first_day_of_month).all()

    # this will calculate what the user will have to pay
    bills_to_pay = Bill.query.filter(Bill.spender_id != select_user(current_user),
                                     Bill.spend_date >= first_day_of_month).all()

    # calculate what the user will have to pay
    to_pay = calculation(bills_to_pay, to_pay=True)

    # calculate what the user will receive
    to_receive = calculation(bills_to_receive)

    final_payment_dict = {}
    for individual_bill in to_receive:
        if individual_bill in to_pay:
            final_payment_dict[individual_bill] = (to_receive[individual_bill] - to_pay[individual_bill])
        else:
            final_payment_dict[individual_bill] = (to_receive[individual_bill])

    for individual_bill in to_pay:
        if individual_bill not in to_receive:
            final_payment_dict[individual_bill] = (-(to_pay[individual_bill]))

    balance = 0
    for final_payment in final_payment_dict:
        balance += final_payment_dict[final_payment]


    payment_dict = {}
    for user_id in final_payment_dict:
        user = db.session.execute(db.select(User).where(User.id == user_id)).scalar()
        payment_dict[user.name] = final_payment_dict[user_id]
    return [payment_dict, balance]

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
            to_give_set.add(bill_id.spender_id)

        # creating dictionary of individual bill
        bill_dict = {
            "amount": bill_id.amount,
            "with_whom": share_among,
            "how_many_to split": len(share_among),
            "spender_id": bill_id.spender_id, }


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

@app.route("/calculate_all")
def calculate_all():
    query = Payment.query.all()
    for i in query:
        if datetime.now().month == i.calculation_date.month or i.calculation_date < date.today() - timedelta(days=60):
            db.session.delete(i)
            db.session.commit()
    all = {}
    user = User.query.all()
    for current_user in user:
        all[current_user.name] = payment(current_user)[0]
    individual_total = {}
    for individual in all:
        individual_total[individual]= sum(all[individual].values())
    new_payment = Payment(
        payment_dict = individual_total,
        calculation_date = date.today()
        )
    db.session.add(new_payment)
    db.session.commit()
    page = request.args.get('page', 1, type=int)
    per_page = 1
    data = Payment.query.paginate(page=page, per_page=per_page, error_out=True)
    return render_template ("all_calculation.html", data = data,is_logged=current_user.is_authenticated)


@app.route("/add_bill", methods=["GET", "POST"])
@login_required
def add_bills():
    bill_form = BillForm()
    results = db.session.execute(db.select(User).where(User.id != select_user(current_user))).scalars().all()

    bill_form.split_with.choices = [(query.id, query.name) for query in results]
    if bill_form.validate_on_submit():
        new_bill = Bill(
            amount=bill_form.amount.data,
            spend_type=bill_form.spend_catagorey.data,
            spend_date=date.today(),
            spender_id=select_user(current_user),
        )
        db.session.add(new_bill)
        db.session.commit()

    # gathering last bill of this user to insert data on Split table
        last_bill = db.session.execute(db.select(Bill.id)
                                       .where(Bill.spender_id == select_user(current_user))
                                       .order_by(Bill.id.desc())).first()
        last_bill_id = last_bill[0]
        for each_user in bill_form.split_with.data:
            split_with = Split(
                split_with=each_user,
                bill_id=last_bill_id, )
            db.session.add(split_with)
            db.session.commit()
        calculate_all()
        return redirect(url_for("home"))

    return render_template("add_bill.html", form=bill_form,
                           is_logged=current_user.is_authenticated)


@app.route("/home")
@login_required
def home():
    current_date = date.today()

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
                           , result=this_month_result, balance = payment(current_user)[1],
                           symbol=symbol, is_logged=current_user.is_authenticated,
                           final_payment_dict=payment(current_user)[0] )


@app.route('/', methods=[ "GET", "POST"])
def login():
    loginform = LoginForm()
    if loginform.validate_on_submit():
        query = db.session.execute(db.select(User).where(User.email == loginform.email.data.lower()))
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
                email=register_form.email.data.lower(),
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

@app.route("/change_password " , methods = ["GET", "POST"])
def change_password():
    form = Password_Reset()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            user.reset_token = secrets.token_urlsafe(30)
            user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            send_password_reset_email(user)
            flash('Check your email for the instructions to reset your password', 'info')
            return redirect(url_for('login'))
        else:
            flash("No User found with the email.")
            return render_template("password_reset.html",form = form, change = True )
    return render_template("password_reset.html",form = form, change = True )

def send_password_reset_email(user):
    reset_url = url_for('reset_password', token=user.reset_token, _external=True)
    msg = Message('Password Reset Request', sender='hopsanjeev@gmail.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
    {reset_url}
    If you did not make this request, ignore this email.
    '''
    mail.send(msg)
@app.route("/reset_password/<token>", methods = ["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).filter(User.reset_token_expiration > datetime.utcnow()).first()
    if not user:
        flash('Invalid or expired reset token', 'warning')
        return redirect(url_for('change_password'))
    form = Conform_Password()
    if form.validate_on_submit():
        if form.password.data != form.conform_password.data:
            flash("Password did not match. Try again.")
            return redirect(url_for('reset_password', token = user.reset_token))
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2', salt_length=16)
        user.password = hashed_password
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        flash('Your password has been reset!', 'success')
        return redirect(url_for('login'))
    return render_template("conform_password.html", form = form)

@app.route('/bills')
@login_required
def bills():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    data = Bill.query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('bill.html', data=data, is_logged=current_user.is_authenticated)

@app.route("/mybill")
def my_bill():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    #filter_conditions = {spender_id:select_user(current_user)}
    data = Bill.query.filter_by(spender_id = select_user(current_user)).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('bill.html', data = data, is_logged=current_user.is_authenticated, my_bill = True)
@app.route("/edit_bill<id>", methods = ["POST","GET"])
@login_required
def edit(id):
    bill = Bill.query.filter_by(id = id).first()

    results = db.session.execute(db.select(User).where(User.id != select_user(current_user))).scalars().all()
    bill_form = BillForm(
        amount= bill.amount,
        spend_catagorey = bill.spend_type,
    )

    if bill_form.validate_on_submit():
        bill.amount = bill_form.amount.data
        bill.spend_type = bill_form.spend_catagorey.data
        if len(bill_form.split_with.data) == len(bill.who_pay):
            for i in range(len(bill.who_pay)):
                bill.who_pay[i].split_with = bill_form.split_with.data[i]
        elif len(bill_form.split_with.data) < len(bill.who_pay):
            for i in range(len(bill_form.split_with.data)):
                bill.who_pay[i].split_with = bill_form.split_with.data[i]
            for i in range(len(bill_form.split_with.data),len(bill.who_pay)):
                db.session.delete(bill.who_pay[i])
        else:
            for i in range(len(bill.who_pay)):
                bill.who_pay[i].split_with = bill_form.split_with.data[i]
            for i in range(len(bill.who_pay), len(bill_form.split_with.data)):
                new_split = Split(
                    split_with = bill_form.split_with.data[i],
                    bill_id = bill.id
                )
                db.session.add(new_split)


        db.session.commit()
        return redirect(url_for("my_bill"))

    bill_form.split_with.choices = [(query.id, query.name) for query in results]
    return render_template("add_bill.html" , form = bill_form,is_logged=current_user.is_authenticated)

@app.route("/dekete_bill <id>")
def delete(id):
    bill = Bill.query.filter_by(id = id).first()
    print(id)
    splits = bill.who_pay
    for split in splits:
        db.session.delete(split)
        db.session.commit()
    db.session.delete(bill)
    db.session.commit()
    return redirect(url_for("my_bill"))


if __name__ == "__main__":
    app.run(debug=True, port=5004)
