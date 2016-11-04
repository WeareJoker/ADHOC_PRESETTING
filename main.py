import os

from flask import Flask, render_template, session
from flask import redirect
from flask import request
from flask import url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = 'development-key'


def get_interface_by_script():
    return os.popen('bash shell_scripts/get_interface.sh').read().split()[0]


@app.route('/refresh')
def refresh():
    raw_essid_data = os.popen('iwlist %s scan | grep ESSID' % get_interface_by_script()).read()
    essid_list = [essid.strip()[7:-1] for essid in raw_essid_data.split('\n')]
    session['essid_list'] = essid_list

    return redirect(url_for('index'))


@app.route('/get_passwd/<string:ssid>', methods=['GET', 'POST'])
def get_password(ssid=None):
    if ssid is None:
        return redirect(url_for('index'))
    if request.method == 'GET':
        return render_template('passwd.html',
                               ssid=ssid)

    elif request.method == 'POST':
        # Command Injection~!
        password = request.form['password']
        result = os.popen('bash shell_scripts/connect_wifi.sh %s %s' % (ssid, password)).read()
        if result == "You're connected.\n":
            return "Success!"
        else:
            return render_template('passwd.html',
                                   ssid=ssid,
                                   message="Fail...")


@app.route('/')
def index():
    if session.get('essid_list') is None:
        return redirect(url_for('refresh'))
    return render_template('main.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
