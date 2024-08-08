from flask import Flask, render_template, request, redirect, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import pickle
import numpy as np
import re
import pymysql
import logging

logging.basicConfig(level=logging.INFO)

popular_df = pickle.load(open('popular.pkl', 'rb'))
pt = pickle.load(open('pt.pkl', 'rb'))
books = pickle.load(open('books.pkl', 'rb'))
similarity_scores = pickle.load(open('similarity_scores.pkl', 'rb'))

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Sri.1185'
app.config['MYSQL_DB'] = 'book_recommendation_system'

mysql = MySQL(app)

# Load necessary data
popular_df = pickle.load(open('popular.pkl', 'rb'))


@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html',
                               book_name=list(popular_df['Book-Title'].values),
                               book_authors=list(popular_df['Book-Author'].values),
                               image=list(popular_df['Image-URL-M'].values),
                               votes=list(popular_df['num_ratings'].values),
                               rating=list(popular_df['avg_rating'].values),
                               username=session['username'])
    else:
        return redirect('/login')


@app.route('/recommend')
def recommend_ui():
    if 'username' in session:
        return render_template('recommend.html')
    else:
        return redirect('/login')

@app.route('/recommend_books', methods=['POST'])
def recommend_books():
    if 'username' in session:
        user_input = request.form.get('user_input').lower()
        try:
            filtered_titles = pt.index[pt.index.str.lower().str.contains(user_input)]
            if len(filtered_titles) == 0:
                return render_template('recommend.html', data=[])

            index = np.where(pt.index == filtered_titles[0])[0][0]
            similar_items = sorted(list(enumerate(similarity_scores[index])), key=lambda x: x[1], reverse=True)[1:5]

            data = []
            for i in similar_items:
                item = []
                temp_df = books[books['Book-Title'] == pt.index[i[0]]]
                item.extend(list(temp_df.drop_duplicates('Book-Title')['Book-Title'].values))
                item.extend(list(temp_df.drop_duplicates('Book-Title')['Book-Author'].values))
                item.extend(list(temp_df.drop_duplicates('Book-Title')['Image-URL-M'].values))
                data.append(item)

            return render_template('recommend.html', data=data)
        except IndexError:
            return render_template('recommend.html', data=[])
    else:
        return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM login WHERE username = %s", (username,))
            user = cur.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                session['username'] = username
                return redirect('/')
            else:
                error_message = 'Invalid username or password'
                return render_template('login.html', message=error_message)
        except Exception as e:
            print("Error during login:", e)  # Print detailed error message
            error_message = 'An error occurred while logging in'
            return render_template('login.html', message=error_message)
        finally:
            cur.close()
    else:
        if 'username' in session:
            return redirect('/')
        else:
            return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO login (username, password) VALUES (%s, %s)", (username, hashed_password.decode('utf-8')))
            mysql.connection.commit()
            return redirect('/login')
        except Exception as e:
            print("Error during signup:", e)
            error_message = 'An error occurred while signing up'
            return render_template('signup.html', message=error_message)
        finally:
            cur.close()

    else:
        if 'username' in session:
            return redirect('/')
        else:
            return render_template('signup.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

@app.route('/delete_account')
def delete_account():
    if 'username' in session:
        try:
            cur = mysql.connection.cursor()
            cur.execute("DELETE FROM login WHERE username = %s", (session['username'],))
            mysql.connection.commit()
            session.pop('username', None)
            return redirect('/login')
        except Exception as e:
            print("Error:", e)
            error_message = 'An error occurred while deleting the account'
            return render_template('index.html', message=error_message)
        finally:
            cur.close()
    else:
        return redirect('/login')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']

        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM login WHERE username = %s", (username,))
            user = cur.fetchone()

            if not user:  # If user does not exist
                error_message = 'Invalid username'
                return render_template('forgot.html', message=error_message)

            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cur.execute("UPDATE login SET password = %s WHERE username = %s",
                        (hashed_password.decode('utf-8'), username))
            mysql.connection.commit()
            print("Password updated successfully")
            return redirect('/login')
        except Exception as e:
            print("Error during password update:", e)
            error_message = 'An error occurred while updating the password'
            return render_template('forgot.html', message=error_message)
        finally:
            cur.close()
    else:
        return render_template('forgot.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query the Admin table to check credentials
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM Admin WHERE username = %s", (username,))
        admin = cur.fetchone()
        cur.close()

        if admin and bcrypt.checkpw(password.encode('utf-8'), admin[2].encode('utf-8')):
            session['admin_logged_in'] = True
            return redirect('/admin_dashboard')
        else:
            error_message = 'Invalid admin username or password'
            return render_template('admin_login.html', message=error_message)
    else:
        return render_template('admin_login.html')


@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin_logged_in' in session:
        try:
            if request.method == 'POST':
                search_query = request.form['search_query']
                cur = mysql.connection.cursor()
                cur.execute("SELECT * FROM books WHERE `Book-Title` LIKE %s", ('%' + search_query + '%',))
                search_results = cur.fetchall()
                cur.close()

                cur = mysql.connection.cursor()
                cur.execute("SELECT * FROM books LIMIT 1")
                column_names = [desc[0] for desc in cur.description]
                cur.close()

                books = [dict(zip(column_names, row)) for row in search_results]

                return render_template('admin_dashboard.html', books=books, search_query=search_query)

            return render_template('admin_dashboard.html')
        except Exception as e:
            print("Error fetching books:", e)
            error_message = 'An error occurred while fetching books'
            return render_template('admin_dashboard.html', message=error_message)
    else:
        return redirect('/admin_login')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect('/admin_login')

@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        image_url = request.form['image_url']
        isbn = request.form['isbn']
        publisher = request.form['publisher']
        year_of_publication = request.form['year_of_publication']

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO books (`Book-Title`, `Book-Author`, `Image-URL-M`, `ISBN`, `Publisher`, `Year-Of-Publication`) VALUES (%s, %s, %s, %s, %s, %s)", (title, author, image_url, isbn, publisher, year_of_publication))
            mysql.connection.commit()
            flash('Book successfully added', 'success')
        except Exception as e:
            print("Error during adding book:", e)
            mysql.connection.rollback()
            flash('An error occurred while adding the book', 'error')
        finally:
            cur.close()

    return render_template('add_book.html')


@app.route('/search_book', methods=['GET'])
def search_book():
    if 'username' not in session:
        return redirect('/login')

    search_query = request.args.get('search_query', '')

    try:
        cur = mysql.connection.cursor()
        sql_query = "SELECT `Book-Title`, `Book-Author`, `Image-URL-M` FROM books WHERE `Book-Title` LIKE %s"
        logging.info("SQL Query: %s", sql_query)
        logging.info("Search Query: %s", search_query)
        cur.execute(sql_query, ('%' + search_query + '%',))

        # Fetch column names from cursor description
        columns = [desc[0] for desc in cur.description]

        # Convert search results to dictionaries
        search_results = [dict(zip(columns, row)) for row in cur.fetchall()]

        cur.close()
        logging.info("Search Results: %s", search_results)

        return render_template('search_results.html', search_results=search_results, search_query=search_query,
                               username=session['username'])

    except Exception as e:
        # Log the specific error for debugging
        logging.error("Error occurred during search: %s", e)
        # Render a custom error template with the error message
        return render_template('error.html',
                               error_message='An error occurred while searching for books. Please try again later.')


@app.route('/add_admin', methods=['GET', 'POST'])
def add_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO admin (username, password) VALUES (%s, %s)", (username, hashed_password.decode('utf-8')))
            mysql.connection.commit()
            return redirect('/admin_dashboard')
        except Exception as e:
            print("Error during admin creation:", e)
            error_message = 'An error occurred while adding the admin'
            return render_template('add_admin.html', message=error_message)
        finally:
            cur.close()

    else:
        return render_template('add_admin.html')

@app.route('/edit_book', methods=['POST'])
def edit_book():
    try:
        isbn = request.form['isbn']
        field = request.form['field']
        value = request.form['value']

        print("ISBN:", isbn)
        print("Field:", field)
        print("New Value:", value)

        # Update the book details in the database
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE books
            SET `{}` = %s
            WHERE ISBN = %s
        """.format(field.replace('`', '')), (value, isbn))
        mysql.connection.commit()
        cur.close()

        return 'Book details updated successfully'
    except Exception as e:
        print("Error during updating book details:", e)
        return 'Could not update details', 500  # Return an error response with status code 500

@app.route('/delete_book/<string:isbn>', methods=['GET'])
def delete_book(isbn):
    try:
        # Delete the book entry from the database
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM books WHERE ISBN = %s", (isbn,))
        mysql.connection.commit()
        flash('Book successfully deleted', 'success')
    except Exception as e:
        print("Error during deleting book:", e)
        mysql.connection.rollback()
        flash('An error occurred while deleting the book', 'error')
    finally:
        cur.close()
    return redirect('/admin_dashboard')

if __name__ == '__main__':
    app.run(debug=False)