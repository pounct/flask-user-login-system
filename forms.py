from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional


class SignupForm(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired(), Length(max=64)])
    password = PasswordField('Password', validators=[Length(
        min=6, message='Select a stronger password.'), DataRequired()])
    confirm = PasswordField('Confirm Your Password', validators=[
                            DataRequired(), EqualTo('password', message='Passwords must match.')])
    email = StringField('Email', validators=[Length(min=6), Email(
        message='Enter a valid email.'), DataRequired()])
    website = StringField('Website', validators=[Optional()])
    is_admin = BooleanField('Is Admin')
    submit = SubmitField('Sign Up', render_kw={"class": "btn btn-primary"})


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
                        DataRequired(), Email(message='Enter a valid email.')])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Login', render_kw={"class": "btn btn-primary"})


class RequestResetForm(FlaskForm):
    email = StringField(
        validators=[DataRequired(), Length(min=6), Email(
            message='Enter a valid email.')], render_kw={"placeholder": "Your Email"})
    submit = SubmitField('Request Password Reset', render_kw={
                         "class": "btn btn-primary"})


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password', render_kw={
                         "class": "btn btn-primary"})
