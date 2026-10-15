@app.route('/changepassword', methods=['POST'])
def changepassword():
    newpassword = request.form['newpassword']
    user = request.form['username']
    u = User.query.filter(User.username == user).first()
    if not u:
        return "Error"
~>    u.password = newpassword
    db_session.commit()
    return "Change Password Successful"
