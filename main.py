import os

from flask import Flask, render_template, session
from flask import redirect
from flask import request
from flask import url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = 'development-key'


def get_interface_by_script():
    result = os.popen('bash shell_scripts/get_interface.sh').read().split()
    if result:
        return result[0]
    else:
        return None


@app.route('/refresh')
def refresh():
    # catch channel and essid from "iwlist" command.
    # raw_essid_data = os.popen('iwlist %s scan | grep -E "ESSID|Channel:"' % get_interface_by_script()).read()

    raw_essid_data = os.popen('iwlist %s scan | grep ESSID' % "wlx18a6f71cbc0b").read()
    essid_list = [essid.strip()[7:-1] for essid in raw_essid_data.split('\n')]

    now_decrypting = os.popen('ps -e | grep dot11decrypt').read()
    if not now_decrypting:
        now_decrypting = 0
    else:
        now_decrypting = 1

    # ap_info_hash = []
    # for info in raw_essid_data.split('\n'):
    #    # first, is it channel?
    #    #is_channel = info.find("Channel")
    #    #if is_channel != -1:   # takes much cost
    #    if info.strip()[0] == "C" : # is it channel?
    #       chan = info.strip()[8:]
    #    elif info.strip()[0] == "E" # is it essid?
    #        ess = info.strip()[7:-1]
    #        ap_info_hash

    session['essid_list'] = essid_list
    session['now_decrypting'] = now_decrypting
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


@app.route('/get_passwd_sniff/<string:ssid>', methods=['GET', 'POST'])
def get_password_sniff(ssid=None):
    if ssid is None:
        return redirect(url_for('index'))
    if request.method == 'GET':
        return render_template('passwd_sniff.html',
                               ssid=ssid)

    elif request.method == 'POST':
        password = request.form['password']
        # get channel info
        iface = "wlx18a6f71cbc0b"
        raw_channel_data = os.popen('iwlist %s scan | grep -E "ESSID|Channel:"' % iface).read()

        tmp_channel = None

        for info in raw_channel_data.split('\n'):
            # is it ESSID?
            strip_data = info.strip()
            if tmp_channel is not None and strip_data[0] == "E" and strip_data[7:-1] == ssid:
                channel = tmp_channel
                break

            # is it channel?
            else:
                tmp_channel = strip_data[8:]

        with open("/pjhs/autorun_setting", "wt") as f:
            f.write("%s %s %s %s" % ("wpa", ssid, password, channel))
        os.popen('/pjhs/dot11decrypt/build/dot11decrypt %s %s:%s:%s &' % (iface, "wpa", ssid, password))
        session['now_decrypting'] = 1
    return redirect(url_for('index'))


@app.route('/stop_sniff')
def stop_sniff():
    dot11_pid = os.popen("ps -ef | grep dot11decrypt | awk '{print $2}'").read()
    print(dot11_pid)
    if len(dot11_pid.split('\n')) < 2:
        return redirect(url_for('index'))

    os.popen("kill -9 %s" % dot11_pid)
    session['now_decrypting'] = 0
    return redirect(url_for('index'))


@app.route('/')
def index():
    if session.get('essid_list') is None:
        return redirect(url_for('refresh'))
    return render_template('main.html', now_decrypting=session['now_decrypting'])


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
