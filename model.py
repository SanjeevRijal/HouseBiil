from sqlalchemy.orm import relationship
from flask_login import UserMixin
from config import db

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

