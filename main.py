from flask import Flask, render_template, request, redirect, url_for, session, flash
import csv
import logging
from logging.handlers import RotatingFileHandler
import os
import base64
import bcrypt
from encryption import load_or_create_key, encrypt_data, decrypt_data  # Ensure correct imports
from flask_wtf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DecimalField, SubmitField
from wtforms.validators import  InputRequired,DataRequired, Length, NumberRange
from decimal import Decimal, getcontext

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = app.secret_key
csrf = CSRFProtect(app)# Generating a random secret key
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
formatter = logging.Formatter('%(asctime)s %(message)s')
file_handler = RotatingFileHandler('app.log', maxBytes=1024 * 1024, backupCount=10)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
server_handler = logging.StreamHandler()
server_handler.setFormatter(formatter)
server_handler.setLevel(logging.INFO)
app.logger.propagate = False
root_logger = logging.getLogger()
root_logger.addHandler(server_handler)
root_logger.setLevel(logging.INFO)
getcontext().prec = 3

def register_user(username, password, recovery_code, bank_balance, role):
  # Load or create encryption key for the user
  key, salt = load_or_create_key(username)  # Adjusted to handle key and salt

  # Hash the password
  hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

  # Encrypt the rest of the user data
  encrypted_recovery_code = encrypt_data(recovery_code, key, salt)
  encrypted_bank_balance = encrypt_data(str(bank_balance), key, salt)  # Convert to string if not already
  encrypted_role = encrypt_data(role, key, salt)

  updated = False
  new_row = [username, 
     hashed_password.decode('utf-8'), 
     encrypted_recovery_code, 
     encrypted_bank_balance, 
     encrypted_role, 
     base64.b64encode(key).decode('utf-8'), 
     base64.b64encode(salt).decode('utf-8')]

  rows = []
  try:
      with open('user_credentials.csv', 'r', newline='') as csvfile:
          reader = csv.reader(csvfile)
          rows = [row for row in reader if row]  # Read and store existing data
          for row in rows:
              if row[0] == username:  # Check if the username already exists
                  index = rows.index(row)
                  rows[index] = new_row  # Update existing user data
                  updated = True
                  break
  except FileNotFoundError:
      # File not found
      pass

  # Open file in write mode to add new or update existing user
  mode = 'w' if updated or not rows else 'a'  # 'w' to overwrite if updating, 'a' to append if new
  with open('user_credentials.csv', mode, newline='') as csvfile:
      writer = csv.writer(csvfile)
      if not rows:  # If no rows exist, it's a new file, write header
          writer.writerow(['Username', 'Password', 'Recovery code', 'Bank balance', 'Role', 'Key'])
      if updated:
          writer.writerows(rows)  # Write all rows back if updated
      else:
          writer.writerow(new_row)  # Append the new row only

  return True


def delete_user(username):
    Found = False
    try:
        with open('user_credentials.csv', 'r', newline='') as csvfile:
            reader = csv.reader(csvfile)
            rows = [row for row in reader if row]  # Read all rows

            # Find the row to delete
            for row in rows:
                if row[0] == username:
                    rows.remove(row)
                    Found=True
                    break
            if Found == True:
            # Write the updated rows back to the file
              with open('user_credentials.csv', 'w', newline='') as csvfile:
                  writer = csv.writer(csvfile)
                  writer.writerows(rows)  # Write all rows back to the CSV
            else:
                print(username, "not found in the CSV file.")
    except FileNotFoundError:
        print("User credentials file not found.")
    except Exception as e:
        print(f"Error reading user credentials: {e}")
def search_user(search_username):

    user_info = None
    with open('user_credentials.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['Username'] == search_username:
                # Assuming you have the key for decryption
                decryption_key, salt = load_or_create_key(search_username)
                user_info = {
                    'Username': row['Username'],
                    'Password': '*****',  # Don't display passwords
                    'Recovery code': decrypt_data(row['Recovery code'], decryption_key, salt),
                    'Bank balance': decrypt_data(row['Bank balance'], decryption_key, salt),
                    'Role': decrypt_data(row['Role'], decryption_key, salt)
                }
                break

    if user_info:
        return user_info
    else:
        flash('No user found with that username.')
        return None



def authenticate_user(username, password, recovery_code):
  try:
      with open('user_credentials.csv', newline='') as csvfile:
          reader = csv.DictReader(csvfile)
          for row in reader:
              if username == row['Username']:
                  hashed_password = row['Password'].encode('utf-8')
                  # Check the provided password against the stored hash
                  if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                      key = base64.b64decode(row['Key'])
                      salt = base64.b64decode(row['Salt'])

                      decrypted_recovery_code = decrypt_data(row['Recovery code'], key, salt)
                      if recovery_code == decrypted_recovery_code:
                          decrypted_bank_balance = decrypt_data(row['Bank balance'], key, salt)
                          decrypted_role = decrypt_data(row['Role'], key, salt)

                          return username, decrypted_bank_balance, decrypted_role
  except Exception as e:
      print(f"Error during user authentication: {e}")
  return None, None, None



def get_transaction_history(username):
      transactions = []
      try:
          with open('app.log', 'r') as file:
              for line in file:
                  if f"User '{username}'" in line and ("Deposit" in line or "Withdrawal" in line):
                      transactions.append(line.strip())
      except FileNotFoundError:
          transactions.append("Transaction log file not found.")
      except Exception as e:
          transactions.append(f"An error occurred while processing the log file: {str(e)}")

      # Return None if the transactions list is empty
      if not transactions:
          return None
      return transactions




def update_bank_balance(username, new_balance):
                            try:
                                with open('user_credentials.csv', 'r', newline='') as csvfile:
                                    reader = csv.DictReader(csvfile)
                                    rows = list(reader)

                                with open('user_credentials.csv', 'w', newline='') as csvfile:
                                    fieldnames = ['Username', 'Password', 'Recovery code', 'Bank balance', 'Role', 'Key', 'Salt']  # Include Salt
                                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                                    writer.writeheader()

                                    for row in rows:
                                        if row['Username'] == username:
                                            key = base64.b64decode(row['Key'])
                                            salt = base64.b64decode(row['Salt'])
                                            row['Bank balance'] = encrypt_data(str(new_balance), key, salt)
                                        writer.writerow(row)
                            except Exception as e:
                                print(f"Error updating bank balance: {e}")




@app.route('/login', methods=['GET', 'POST'])
def login():
          form = LoginForm()
          if form.validate_on_submit():
              username = form.username.data
              password = form.one_time_password.data
              recovery_code = form.recovery_code.data
              authenticated_user, bank_balance, role = authenticate_user(username, password, recovery_code)

              if authenticated_user:
                  session['username'] = authenticated_user
                  session['bank_balance'] = bank_balance
                  session['role'] = role

                  if session['role'] == 'admin':
                      app.logger.info(f"Successful login: Admin '{username}' from IP {request.remote_addr}")
                      return redirect(url_for('admin_dashboard'))
                  else:
                      app.logger.info(f"Successful login: '{username}' from IP {request.remote_addr}")
                      return redirect(url_for('dashboard', form=form))
              else:
                  app.logger.warning(f"Failed login attempt: User '{username}' from IP {request.remote_addr}")
                  flash("Login failed. Please check your username, password, and recovery code.")
                  return redirect(url_for('home'))
          else:
              # Always pass 'form' to the template, even if not validating form submission
              return render_template('login.html', form=form)


@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    create_user_form = CreateUserForm(prefix="create")
    delete_user_form = DeleteUserForm(prefix="delete")
    search_user_form = SearchUserForm(prefix="search")
    logout_form = LogoutForm()  # Initialize the logout form

    if 'username' in session and session['role'] == 'admin':
        if request.method == 'POST':
            

            if 'create-create_user' in request.form:
                logging.info("Create user form submitted")
                if create_user_form.validate_on_submit():
                    logging.info("Create user form submitted")
                    new_username = create_user_form.new_username.data
                    new_password = create_user_form.new_password.data
                    new_recovery_code = create_user_form.new_recovery_code.data
                    new_role = create_user_form.new_role.data
                    register_user(new_username, new_password, new_recovery_code, "0", new_role)
                    flash(f"User '{new_username}' created successfully!")

            if 'delete-delete_user' in request.form:
                if delete_user_form.validate_on_submit():
                    logging.info("Delete user form submitted")
                    username_to_delete = delete_user_form.username_to_delete.data
                    delete_user(username_to_delete)
                    flash(f"User '{username_to_delete}' deleted successfully!")
                    return redirect(url_for('admin_dashboard'))

            if 'search-search_username' in request.form:
                logging.info("Search user form submitted")
                if search_user_form.validate_on_submit():
                   
                    username = search_user_form.search_username.data
                    logging.info("Searching for user with username: %s", username)
                    return redirect(url_for('user_info', username=username))
                    
                else:
                    logging.info("Search form errors: %s", search_user_form.errors)
                    flash("Search form is invalid. Please check the input.")

            elif 'logout' in request.form:
                logging.info("Logout form submitted")
                if logout_form.validate_on_submit():
                    session.clear()
                    return redirect(url_for('home'))
        return render_template('admin.html', name=session['username'],
                               create_user_form=create_user_form,
                               delete_user_form=delete_user_form,
                               search_user_form=search_user_form,
                               logout_form=logout_form)
    else:
        return redirect(url_for('home'))


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
          form_deposit = DepositForm(prefix="deposit")
          form_withdraw = WithdrawForm(prefix="withdraw")
          form_logout = LogoutForm(prefix="logout")

          if 'username' not in session:
              return redirect(url_for('login'))  # Ensure the user is logged in

          if request.method == 'POST':
              if form_logout.validate_on_submit():
                  session.clear()
                  return redirect(url_for('login'))
              if form_deposit.validate_on_submit() and 'deposit' in request.form:
                  # Process deposit here
                  
                  flash('Deposit successful')
                  return redirect(url_for('dashboard'))
              if form_withdraw.validate_on_submit() and 'withdraw' in request.form:
                  # Process withdrawal here
                    # Negative for withdrawal
                  flash('Withdrawal successful')
                  return redirect(url_for('dashboard'))

          return render_template('dashboard.html', name=session.get('username'), bank_balance=session.get('bank_balance', 0),
                                 form_deposit=form_deposit, form_withdraw=form_withdraw, form_logout=form_logout)

@app.route('/', methods=['GET'])
def home():
      form = LoginForm()  # Ensure this form is instantiated
      return render_template('login.html', form=form)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/logout_admin', methods=['POST'])
def logout_admin():
    session.clear()
    return redirect(url_for('home'))

@app.route('/deposit', methods=['POST'])
def deposit():
    if 'username' in session:
        deposit_amount = float(request.form.get('deposit_amount', 0))
        if deposit_amount > 0:
            session['bank_balance'] = round(float(session.get('bank_balance', 0)) + deposit_amount, 2)
            update_bank_balance(session['username'], session['bank_balance'])
            app.logger.info(f"Deposit: User '{session['username']}' deposited ${deposit_amount}. New balance: ${session['bank_balance']}")
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('home'))

@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'username' in session:
        withdraw_amount = float(request.form.get('withdraw_amount', 0))
        bank_balance = float(session.get('bank_balance', 0))
        if withdraw_amount > 0 and bank_balance >= withdraw_amount:
            session['bank_balance'] = bank_balance - withdraw_amount
            update_bank_balance(session['username'], session['bank_balance'])
            app.logger.info(f"Withdrawal: User '{session['username']}' withdrew ${withdraw_amount}. New balance: ${session['bank_balance']}")

        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('home'))

@app.route('/transaction_history')
def transaction_history():
          if 'username' in session:
              username = session['username']
              transactions = get_transaction_history(username)
              if transactions and "error occurred" not in transactions[0].lower():
                  return render_template('transaction_history.html', name=username, transactions=transactions)
              else:
                    # Display error message from the transactions list
                  return redirect(url_for('dashboard'))  # Redirect to a safe page
          else:
              flash("User not logged in.")
              return redirect(url_for('home'))


@app.route('/log_history')
def log_history():
    if 'username' in session and session.get('role') == 'admin':
        successful_attempts = []
        unsuccessful_attempts = []

        with open('app.log', 'r') as log_file:
            for line in log_file:
                if "Successful login" in line:
                    successful_attempts.append(line.strip())
                elif "Failed login attempt" in line:
                    unsuccessful_attempts.append(line.strip())

        return render_template('log_history.html', successful_attempts=successful_attempts, unsuccessful_attempts=unsuccessful_attempts)
    else:
        return redirect(url_for('home'))

@app.route('/user_log_history/<username>')
def user_log_history(username):

    log_entries = []
    try:
        with open('app.log', 'r') as file:
            for line in file:
                if f"'{username}'" in line:
                    log_entries.append(line.strip())
        if not log_entries:
            flash(f"No log history found for user '{username}'")
            return redirect(url_for('admin_dashboard'))
    except FileNotFoundError:
        flash("Log file not found.")
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f"An error occurred while processing the log file: {e}")
        return redirect(url_for('admin_dashboard'))

    return render_template('user_log_history.html', log_entries=log_entries, username=username)

@app.route('/user_info/<username>')
def user_info(username):
      print("reach")
      try:
          user_info = search_user(username)
          if user_info:
              # Assuming sensitive information is already handled by search_user
              return render_template('user_info.html', user_info=user_info)
          else:
              flash(f"No user found with username '{username}'")
      except Exception as e:
          flash("An error occurred while retrieving user information.")
          app.logger.error(f"Failed to retrieve user information for {username}: {e}")

      return redirect(url_for('admin_dashboard'))

class CreateUserForm(FlaskForm):
  new_username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
  new_password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
  new_recovery_code = StringField('Recovery Code', validators=[DataRequired(), Length(min=3, max=50)])
  new_role = StringField('Role', validators=[DataRequired(), Length(min=4, max=5)])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    one_time_password = PasswordField('One-Time Password', validators=[DataRequired()])
    recovery_code = StringField('Recovery Code', validators=[DataRequired()])

class BalanceForm(FlaskForm):
  deposit_amount = DecimalField('Deposit Amount', validators=[DataRequired(), NumberRange(min=0.01)])
  withdraw_amount = DecimalField('Withdraw Amount', validators=[DataRequired(), NumberRange(min=0.01)])

class DeleteUserForm(FlaskForm):
  username_to_delete = StringField('Username to Delete', validators=[DataRequired(), Length(min=3, max=25)])
  submit_delete = SubmitField('Delete User')

class SearchUserForm(FlaskForm):
    search_username = StringField('Username', validators=[DataRequired()])


class LogoutForm(FlaskForm):
  pass

class DepositForm(FlaskForm):
    deposit_amount = DecimalField('Deposit Amount', validators=[
    InputRequired(), 
    NumberRange(min=0.01, message='The amount must be at least $0.01')
])
class WithdrawForm(FlaskForm):
  withdraw_amount = DecimalField('Withdraw Amount', validators=[
    InputRequired(), 
    NumberRange(min=0.01, message='The amount must be at least $0.01')
])
if __name__ == '__main__':
    app.run(debug=True)